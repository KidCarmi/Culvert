# Authentication rules (Auth Policy) — who must authenticate, and how

**Applies to:** every deployment that proxies HTTP or CONNECT traffic.

**Audience:** security administrators who decide which clients may skip
authentication, which must present credentials, and which must sign in through
SSO. For the break-glass control over exemptions, see
[`authentication-kill-switch.md`](authentication-kill-switch.md).

---

## 1. What it does

Culvert decides each request in two stages:

1. **Stage 1, authentication rules** decide *how the client authenticates*.
2. **Stage 2, access rules** decide *whether the request is allowed*.

A Stage-1 outcome is never an allow. A client that an authentication rule
exempts still has to pass the blocklist, threat feeds, access rules and the
default action, exactly like any other request.

Authentication rules are evaluated only for a request that presents **no
credentials**: no valid session cookie and no `Proxy-Authorization` header. A
request that carries a valid session or valid credentials is authenticated with
its identity and no rule is consulted. A request that carries a
`Proxy-Authorization` header that is wrong or malformed gets a `407` and is
never exempted (`proxy.go` `resolveRequestAuth`, `authpolicy.go`
`resolveNoCredAuthOutcome`).

SOCKS5 has its own handshake and does not evaluate authentication rules; a rule
with `protocol: "socks5"` is rejected.

## 2. Outcomes

The first enabled rule that matches, in priority order (lowest number first),
decides the outcome. Rules of all three outcomes share that one order.

| Outcome | What the client sees | Reaches Stage 2 |
|---|---|---|
| `Exempt` | Nothing. No challenge, no identity. The request is logged with `authSource=exempt`. | Yes |
| `CredentialRequired` | `407` with `Proxy-Authenticate: Basic`. A browser is not redirected to SSO. | Only after it retries with valid credentials |
| `SSORequired` | A browser gets a `302` to the identity provider, or to a selection page when more than one provider is eligible. Any other client, and every `CONNECT`, gets `403`. | Only after sign-in creates a session |

For `SSORequired`, a *browser* is a non-`CONNECT` request that sends
`Sec-Fetch-Mode: navigate` or an `Accept` header containing `text/html`
(`internal/clientclass`). The User-Agent is not consulted. HTTPS through an
explicit proxy arrives as `CONNECT`, so an `SSORequired` rule answers it with
`403` until the user has a session from a plain-HTTP navigation; scope such
rules with `protocol: "http"` or pair them with a `CredentialRequired` rule for
service clients.

When no rule matches, the **default authentication behavior** applies (§5).

## 3. Rule fields

| Field | Required | Notes |
|---|---|---|
| `name` | Yes | Unique across authentication and access rules (case-insensitive). |
| `subjectMatch` | Yes | Source scope. `{"schemaVersion":1,"all":[{"type":"cidr","values":[…]}]}`. Each value is a CIDR or a single IP. `cidr` is the only supported type; identity-based types (`user`, `group`, …) are rejected because no identity exists yet. |
| `destFQDN`, `destCategory`, `destCategoryGroup` | See notes | The destination. `CredentialRequired` and `SSORequired` require at least one. `Exempt` requires one, or `auth.broadExemption`. |
| `auth.outcome` | Yes | `Exempt`, `CredentialRequired` or `SSORequired`. |
| `auth.owner`, `auth.reason` | Yes | Who asked for the rule and why. Both are refused when blank. |
| `auth.expiresAt` | No | RFC 3339 timestamp. After it, the rule stops matching but stays configured. |
| `auth.protocol` | No | `""` (any), `http` or `connect`. |
| `auth.method` | No | HTTP method. Ignored when `protocol` is `connect`. |
| `auth.broadExemption` | No | `Exempt` only. Acknowledges an exemption for every destination from the matched sources. |
| `auth.providerRefs` | No | `SSORequired` only. Up to 16 identity-provider profile IDs. Empty means every enabled OIDC or SAML provider. Rejected on the other outcomes. |
| `schedule` | No | Same shape as on access rules. A rule whose time zone cannot be resolved never matches. |
| `enabled` | No | Defaults to `true`. |

`providerRefs` must name enabled OIDC or SAML profiles when the rule is saved.
LDAP profiles are refused: LDAP validates presented credentials and cannot run
an interactive sign-in. If a referenced profile is later disabled or deleted,
the rule is kept and the reference is ignored at run time; when none remains
eligible, the rule answers `403` to every matched client.

Every check fails closed. A rule that is disabled, expired, outside its
schedule, or malformed does not match, and evaluation continues with the next
rule.

## 4. Managing rules

**GUI:** Policies → **Authentication Rules**. Viewers can read the list; adding,
editing, deleting and reordering require the `admin` role (access rules need
only `operator`).

**API** (`ui_authpolicy.go`):

| Call | Role | Purpose |
|---|---|---|
| `GET /api/authpolicy` | viewer | Rules with their warnings, the rulebase `version`, and the kill-switch state. |
| `POST /api/authpolicy` | admin | Create. Returns the stored rule and its warnings. |
| `PUT /api/authpolicy?id=<rule id>` | admin | Replace a rule. |
| `DELETE /api/authpolicy?id=<rule id>` | admin | Delete a rule. |
| `POST /api/authpolicy/reorder` | admin | Body `{"ids":[…]}` listing every authentication rule exactly once, in the wanted order. Access-rule order is not affected. |

`?priority=<n>` is still accepted in place of `?id=` and is what the GUI sends;
prefer `?id=`, which keeps pointing at the same rule after a reorder. Every
write accepts `?ifVersion=<version>` and is refused with `409` when the rulebase
has changed since that version was read. `POST /api/policy` refuses
authentication rules.

```sh
curl -sS -u "$ADMIN_USER" -X POST -H 'Content-Type: application/json' \
  "https://$ADMIN_HOST/api/authpolicy" -d '{
    "name": "printers-to-vendor-update",
    "subjectMatch": {"schemaVersion": 1, "all": [{"type": "cidr", "values": ["10.20.30.0/28"]}]},
    "destFQDN": "updates.vendor.example",
    "auth": {"outcome": "Exempt", "owner": "it-print", "reason": "printers cannot authenticate",
             "expiresAt": "2027-06-30T00:00:00Z"}
  }'
```

What a successful write means:

- **It is live immediately.** Authentication rules are never staged. With
  Require Commit on, they still take effect at once, and an open access-policy
  draft becomes stale: its commit is refused, and `GET /api/policy/draft`
  reports `baseStale`.
- **It is on disk.** If the rulebase cannot be persisted the change is rolled
  back and the call fails.
- **It is audited and versioned.** Audit actions are `authpolicy.add`,
  `authpolicy.update`, `authpolicy.remove` and `authpolicy.reorder`. Each write
  creates a configuration version, so a configuration rollback restores the
  authentication rules of that version together with the access rules.
- **It reaches the cluster.** Authentication rules travel with the policy rules
  the Control Plane sends to Data Plane nodes. A node drops a received
  authentication rule that fails validation rather than enforce it.

## 5. Default authentication behavior

This setting decides the outcome for a request without credentials that no
authentication rule matches.

| Value | GUI label | Effect |
|---|---|---|
| `Default` | Require authentication | The client is challenged: a `407`, or a redirect to the sign-in page when an SSO provider is configured and the request is not `CONNECT` and carries a `Mozilla` User-Agent. |
| `Exempt` | Open unmatched traffic | The request continues to Stage 2 without an identity, logged with `authSource=unauth`. |

- **GUI:** Settings → **Default authentication behavior**.
- **API:** `PUT /api/settings/default-auth-outcome` with
  `{"defaultAuthOutcome":"Default"}` or `"Exempt"` (admin). Read it from
  `GET /api/settings`. Any other value is refused.
- **Default value:** `Default`. Choosing the open mode in the first-run setup
  wizard sets `Exempt`.

Things that differ from authentication rules:

- **Rules still enforce under the open default.** `CredentialRequired` and
  `SSORequired` rules challenge matching traffic whatever the default is. The
  `auth_default_exempt_rules_now_enforce` Diagnostics row lists them.
- **It is stored with the admin roster** (`ui_users.json`), not with the policy.
  It is audited as `settings.update` but creates no configuration version, and a
  configuration rollback does not change it. An unreadable or unrecognized
  stored value is treated as `Default`.
- **It is per node.** The Control Plane includes its value in the configuration
  it sends, for information only; a Data Plane node does not apply it
  (`config_surfaces.go`, `default_auth_outcome`). Each node uses its own stored
  value.
- **A node with nothing to verify and no accounts skips Stage 1.** With
  `Default`, no credential provider, no working SSO provider and no account at
  all in the admin roster (`ui_users.json`), a challenge could never be
  satisfied. Stage 1 is not entered: no authentication rule is
  evaluated, including `CredentialRequired` and `SSORequired` rules, and every
  request continues to Stage 2 as `unauth` (`authRequired` in
  `resolveRequestAuth`). Only access rules and the default action protect such
  a node. Under `Exempt` the same node does evaluate rules, and a
  `CredentialRequired` rule then answers `407`
  (`TestS3_NoBackend_DefaultInert_ExemptScopedFires`).
- **Admin-console accounts never authenticate proxy traffic.** The accounts in
  the admin roster (`ui_users.json`, the setup-wizard admin, `-user`/`-pass`)
  sign in to the admin UI and API only. A `Proxy-Authorization` (or SOCKS5
  USER/PASS) credential is verified only by a proxy identity provider: an
  enabled LDAP or OIDC profile under **Identity Providers**, or a legacy
  (YAML) LDAP/OIDC provider. Management and data-plane identities are distinct.
- **A roster with accounts but nothing to verify proxy credentials fails
  closed.** If the roster holds accounts and there is no credential or SSO
  provider, Stage 1 is still entered. That is every node whose only accounts
  are admin-console accounts (the admin-only installation), and also a restored
  roster whose only admin role was clamped to viewer or a legacy roster with an
  empty role. A request that matches no rule gets a `407` that nothing can
  satisfy, and any presented credential, including the admin pair, is refused
  (`rosterWithoutVerifier` in `resolveRequestAuth`;
  `TestProxyAuthNoAdmin_AdminOnlyRefusesEveryCredential`,
  `TestAuthEnabled_ClampedAdminRosterHTTPProxyRefused`). Authentication is not
  bypassed: the node refuses that traffic until a proxy identity provider is
  configured. Credential-free requests covered by an `Exempt` rule or the
  `Exempt` default are unaffected.

## 6. Signals

**Diagnostics** (`GET /api/diagnostics`, and the Support bundle):

| Code | Level | Meaning |
|---|---|---|
| `auth_cr_no_credential_provider` | fail | `CredentialRequired` rules exist but nothing can validate a credential. SAML alone does not count, and neither do admin-console accounts. See §5 for what such a node does. |
| `auth_sso_no_idp` | fail | `SSORequired` rules exist but no OIDC or SAML provider is enabled. |
| `auth_sso_rule_no_eligible_provider` | fail | Every `providerRefs` entry of a rule is disabled or deleted; the rule always answers `403`. |
| `auth_sso_providerref_unavailable` | warn | Some, not all, of a rule's `providerRefs` are unavailable. |
| `auth_sso_may_match_non_browser` | warn | An `SSORequired` rule with protocol any or `connect` will answer `403` to non-browser and `CONNECT` clients. |
| `auth_sso_ambiguous_idp` | warn | Several providers are enabled and a rule names none; users see a selection page. |
| `auth_rule_shadowed` | warn | A higher-priority rule covers a lower one. Best effort: no warning is not proof that no rule is shadowed. |
| `auth_default_exempt_rules_now_enforce` | warn | See §5. |
| `auth_exempt_broad_exemption`, `auth_exempt_any_source`, `auth_exempt_wide_source`, `auth_exempt_broad_destination`, `auth_exempt_no_expiry`, `auth_exempt_expired` | warn | An `Exempt` rule covers every destination, every source, a source wider than `/24`, has no expiry, or has expired. |
| `auth_exempt_default_allow` | warn | `Exempt` rules exist while the Stage-2 default action is Allow. |
| `auth_exempt_kill_switch` | warn | See the kill-switch guide. |

The same per-rule warnings are returned as `warnings` on each rule in
`GET /api/authpolicy` and shown as badges in the panel.

**Policy Tester** (`POST /api/policy/test`): the Stage-1 block shows the outcome
and the matched rule for a given source, destination, protocol and method, and
whether Stage 2 would be reached.

**Proxy log and request log:**

| Outcome | Proxy log line | Request-log status |
|---|---|---|
| `Exempt` rule | `AUTH_EXEMPT rule=… id=…` | The Stage-2 result |
| Open default | `AUTH_DEFAULT_EXEMPT (open, no rule)` | The Stage-2 result |
| `CredentialRequired` | `AUTH_CR … action=challenge` | `CRED_REQUIRED` |
| `SSORequired`, redirected | `AUTH_SSO … action=redirect` | `SSO_REDIRECT` |
| `SSORequired`, refused | `AUTH_SSO … action=deny` | `SSO_DENIED` |
| Default, challenged | `AUTH_FAIL (no-credentials)` | `AUTH_FAIL` |
| Open default forced to `Default` by the kill switch, nothing can verify | `AUTH_NO_BACKEND_INERT` | The Stage-2 result |

**Metrics:** `culvert_auth_exempt_decisions_total` (rule exemptions only, not
the open default), `culvert_auth_credential_required_total`,
`culvert_auth_sso_required_total`.

## 7. Recommendations

- Keep the Stage-2 default action at deny. An exemption removes the identity
  from a request, so only source, destination and `authSource` are left for
  access rules to match.
- Write an access rule with `authSource: "exempt"` for each exemption, limited
  to the destinations those clients need.
- Give every `Exempt` rule a destination and an `expiresAt`. Avoid
  `broadExemption` and sources wider than `/24`.
- After each change, run the Policy Tester for one client that should match and
  one that should not, and clear the Diagnostics rows in §6.

## 8. Troubleshooting

| Symptom | Likely cause |
|---|---|
| An exempt device still gets `407` | It sends a `Proxy-Authorization` header (never exempted); a higher-priority `CredentialRequired` rule matches first; the rule is expired, disabled or outside its schedule; the kill switch is engaged; or the proxy sees a different source address than the rule's CIDR. |
| An exempt device gets a block page | The exemption worked. Stage 2 denied the request; add or fix the access rule. |
| `403 Forbidden: destination requires interactive SSO` | An `SSORequired` rule matched a non-browser or `CONNECT` request, or no eligible provider remains. |
| `407` that no credential satisfies | No proxy identity provider is configured (`auth_cr_no_credential_provider` when a `CredentialRequired` rule exists): add an LDAP or OIDC provider, or remove the rule. Admin-console credentials are refused on the proxy by design. |
| A Data Plane node behaves differently for unmatched traffic | The default authentication behavior is per node (§5). |

## References

- Implementation: `authpolicy.go`, `proxy.go` (`resolveRequestAuth`),
  `ui_authpolicy.go`, `ui_config.go` (`apiDefaultAuthOutcome`), `store.go`
  (`DefaultAuthOutcome`), `diagnostics.go`, `diagnostics_auth_sso.go`,
  `proxy_portal.go`, `internal/clientclass`.
- Tests: `authpolicy_slice3_runtime_test.go`, `authpolicy_phase2_slice3_test.go`,
  `authpolicy_phase3_slice4_test.go`, `authpolicy_mutation_durability_test.go`.
- Design records: `roadmap/AUTHENTICATION-POLICY-SPEC.md`,
  `roadmap/AUTH-POLICY-DEFAULTAUTHOUTCOME-SPEC.md`.
- Related: [`authentication-kill-switch.md`](authentication-kill-switch.md),
  [`identity-backend-availability.md`](identity-backend-availability.md).
