# Authentication kill switch — forcing Auth Policy exemptions off

**Applies to:** every deployment that uses Auth Policy `Exempt` rules or the
**Open unmatched traffic** default (`defaultAuthOutcome=Exempt`).

This is the *Authentication* kill switch. It is unrelated to the C2 enforcement
override (`CULVERT_C2_ENFORCE`) and to the MCP emergency kill switch; see
[`docs/design/PRODUCT-TERMINOLOGY.md`](../design/PRODUCT-TERMINOLOGY.md).

---

## 1. What it does

Stage-1 Auth Policy decides *how a client authenticates*. An `Exempt` outcome
lets a client that presents no credentials skip authentication; Stage-2 access
policy still decides whether the request is allowed.

While the kill switch is engaged, the Stage-1 resolver ignores every exemption
(`authpolicy.go` `resolveAuthOutcomeSnapshot`, `proxy.go` `resolveRequestAuth`):

| Configured | With the switch engaged |
|---|---|
| A matching `Exempt` rule | Skipped. Lower-priority auth rules are still evaluated; if none matches, the request gets the `Default` outcome. |
| `defaultAuthOutcome=Exempt` (Open unmatched traffic) | Treated as `Default` (Require authentication). |
| `CredentialRequired` and `SSORequired` rules | Unchanged. |
| Requests that present credentials or a valid session | Unchanged. Exemptions are only ever evaluated for requests without credentials. |
| Stage-2 access rules and the default action | Unchanged. |

The switch only ever makes Stage-1 stricter. It does not disable authentication
and it is not a way to let traffic through.

Use it during an incident when an exemption is suspected of being abused or was
scoped too broadly, and you need every exemption off at once before you have
time to find and edit the rule.

## 2. Two layers

The switch is engaged when **either** layer is set (`authExemptKillSwitchEngaged`).

| | Runtime toggle | Environment variable |
|---|---|---|
| Set with | Auth Policy panel → **Engage kill switch**, or `PUT /api/authpolicy/killswitch` | `CULVERT_AUTHBYPASS_DISABLE` in the process environment |
| Takes effect | Immediately, no restart | At the next start; read once per process |
| Survives a restart | **No.** It is held in memory only | Yes, for as long as the variable is set |
| Cleared with | The same button or API call, or a restart | Unset the variable and restart. The GUI and API cannot clear it |
| Role | `admin` to change, `viewer` to read | Host access |

`CULVERT_AUTHBYPASS_DISABLE` is engaged by `1`, `true`, `yes` or `on`
(case-insensitive, surrounding whitespace ignored). Any other value, including
an unset or empty variable, leaves it clear (`parseAuthBypassDisable`).

Neither layer is replicated. Each Culvert process reads its own environment, and
the runtime toggle changes only the process that served the API call; it is not
part of the configuration the Control Plane sends to Data Plane nodes. In a
multi-node deployment, set the environment variable on every node that must
enforce it.

The runtime toggle writes an `authpolicy.killswitch` audit entry
(`disabled=true|false`). It is not a configuration version: there is nothing to
roll back, and restoring an older configuration version does not change it.

### API

```sh
# Read both layers (viewer)
curl -sS -u "$ADMIN_USER" "https://$ADMIN_HOST/api/authpolicy/killswitch"
# {"engaged":false,"envDisabled":false,"runtimeDisabled":false}

# Engage the runtime layer (admin); send {"disabled":false} to release it
curl -sS -u "$ADMIN_USER" -X PUT -H 'Content-Type: application/json' \
  -d '{"disabled":true}' "https://$ADMIN_HOST/api/authpolicy/killswitch"
```

`GET /api/authpolicy` returns the same object under `killSwitch`.

### Setting the environment variable under Docker Compose

The shipped `docker-compose.yml` passes a fixed list of variables to the `proxy`
service, and `CULVERT_AUTHBYPASS_DISABLE` is not on it. Putting the variable in
`.env` alone therefore has no effect. Add it to the service's `environment:`
list, for example in a `docker-compose.override.yml`:

```yaml
services:
  proxy:
    environment:
      - CULVERT_AUTHBYPASS_DISABLE=1
```

Then recreate the container (`docker compose up -d`) and confirm `envDisabled`
is `true` with the `GET` call above.

## 3. What clients see

The effect depends on which authentication backends the node has
(`auth_killswitch_diag.go`).

| Node state | Formerly exempt clients |
|---|---|
| A proxy credential provider (LDAP/OIDC) or SSO provider is loaded | Must authenticate: a `407` challenge or an SSO redirect, as for any `Default` traffic. Clients that cannot authenticate (devices, scripts) stop working. |
| An OIDC/LDAP profile is enabled but failed to load | Are challenged, but nothing can validate what they send. Fix the profile under Identity Providers; the startup log names the error. |
| The node has an administrator but no proxy provider is enabled (admin-only installation) | Get a `407` that nothing can satisfy; every such request is refused. Admin-console accounts do not authenticate proxy traffic: configure an LDAP or OIDC provider under Identity Providers. |
| The admin roster holds accounts but no usable administrator, and no provider is enabled | Get a `407` that nothing can satisfy; every such request is refused. Restore an administrator with the `--reset-password` break-glass, then configure a proxy provider: an administrator restores admin access, not proxy access. |
| No credential or SSO provider at all | Depends on the authentication rules that remain once exemptions are skipped. A request that now resolves to `Default` is **not** made to authenticate: no challenge is sent, and it falls through to Stage-2 policy, so only your access rules and default action decide it (`TestKillSwitchNoBackend_NoRule_InertStage2`). A request that now matches a `CredentialRequired` rule, one the skipped `Exempt` rule used to mask, gets a `407` that nothing on this node can satisfy, and is refused (`TestKillSwitchNoBackend_ScopedCR_Challenges407`). |

The last row matters in two ways. On a gateway with no authentication backend,
the switch does not by itself block formerly exempt traffic that resolves to
`Default`; block that with a Stage-2 rule instead. But it does cut off any
formerly exempt client whose destination a lower-priority `CredentialRequired`
rule covers. Before engaging the switch on such a node, look in the
authentication rules for a `CredentialRequired` rule below each `Exempt` rule
that covers the same clients and destinations: those clients stop working while
the switch is engaged. Once it is engaged, the Policy Tester (§4) shows the
outcome each request now resolves to.

## 4. Signals

- **Auth Policy panel:** a red **Kill switch engaged** badge naming the layer
  (`env`, `runtime`, or both). With only the environment layer set, the button
  is hidden because the GUI cannot release it.
- **Diagnostics** (`GET /api/diagnostics`, and the Support bundle): a `warn` row
  with code `auth_exempt_kill_switch` while either layer is engaged, and no row
  while clear. Its message names the layer and the backend state from §3. Below
  the `admin` role, the cause and remediation of both "nothing can verify"
  states are withheld, identically, so the row does not reveal whether the
  roster holds a usable administrator.
- **Policy Tester:** the Stage-1 block reports `killSwitch: true` and shows the
  outcome the runtime would resolve.
- **Audit log:** `authpolicy.killswitch` for runtime changes. The environment
  layer produces no audit entry.
- **Metric:** `culvert_auth_exempt_decisions_total` stops increasing while the
  switch is engaged on a node that previously exempted traffic.

## 5. Returning to normal

1. Fix or delete the exemption that caused the incident (Auth Policy panel).
2. Release the runtime layer: **Release runtime kill switch**, or
   `PUT {"disabled":false}`.
3. If the environment layer is set, remove `CULVERT_AUTHBYPASS_DISABLE` from
   the node's environment and restart it.
4. Confirm `engaged` is `false`, the `auth_exempt_kill_switch` Diagnostics row
   is gone, and a formerly exempt client works again.

## 6. Common mistakes

- **Relying on the runtime toggle across a restart.** A restart, upgrade or
  crash clears it and exemptions resume silently. If the incident is still open
  after a restart, engage it again, or use the environment variable.
- **Engaging it on one node of a cluster.** The other nodes keep exempting.
- **Expecting it to block traffic on a gateway with no auth backend.** See §3.
- **Setting the variable to a value such as `enabled`.** Only the four values in
  §2 engage it; anything else is silently treated as clear. Check `envDisabled`.

## References

- Implementation: `authpolicy.go`, `proxy.go` (`resolveRequestAuth`),
  `ui_authpolicy.go` (`apiAuthPolicyKillSwitch`), `auth_killswitch_diag.go`.
- Tests: `authpolicy_slice6_test.go`, `authpolicy_killswitch_api_test.go`,
  `authpolicy_killswitch_nobackend_test.go`.
- Design record: `roadmap/AUTHENTICATION-POLICY-SPEC.md`.
- Related: [`admin-roster-durability.md`](admin-roster-durability.md),
  [`identity-provider-revocation.md`](identity-provider-revocation.md).
