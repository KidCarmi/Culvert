# SOCKS5 and access policy (SWG-901)

The SOCKS5 listener is off unless you set `proxy.socks5_port` (or
`-socks5-port`). When it is on, this page explains which controls apply to a
SOCKS5 connection and how to make it follow the same access policy as HTTP and
CONNECT. The owner has decided SOCKS5 belongs inside the managed boundary
(contract SWG-901, still `open` until `enforce` becomes the default).

## What always applies

In every mode, a SOCKS5 CONNECT passes these checks, in this order, before any
access policy:

1. Startup posture gate, per-IP connection limit, IP filter, rate limit.
2. Authentication. If any account or credential provider exists (an
   admin-console account, the legacy provider, or an enabled profile in the
   identity-provider registry), the client must use username/password
   (RFC 1929). The credential is checked by the **same resolver HTTP proxy
   Basic authentication uses**, restricted to the providers in the table below,
   so a SOCKS5 user resolves to the same identity, groups and authentication
   source as over HTTP. With no account or provider at all, the client connects
   without credentials and is treated as `unauth`.
3. Destination checks: IDNA/length, the blocklist, the **threat-intelligence
   feed**, and plugins — the CONNECT order. A feed-listed domain is refused with
   SOCKS5 reply `0x02` and a `THREAT_BLOCKED` request-log entry, the same as a
   CONNECT.
4. After policy (below): the SSRF guard and the dial.

Request-log entries for authenticated SOCKS5 connections carry the identity and
`auth_source`.

## Which credentials work over SOCKS5

RFC 1929 sends a username and a password once, with no redirect, prompt or
second step. Only providers that can check a username and password directly
can answer it.

| Provider | SOCKS5 | Why |
|---|---|---|
| LDAP / Active Directory profile (identity-provider registry) | Yes | Directory bind with the username and password. Profiles are tried in registry order. |
| Legacy LDAP provider (`config.yaml`) | Yes | Directory bind. |
| OIDC profile, legacy OIDC provider | No — `provider_not_supported_for_socks5` | The proxy credential is a bearer token, and login is an interactive browser flow. |
| SAML profile | No — `provider_not_supported_for_socks5` | Browser-only. |
| Admin-console accounts | **Never** | An administrative credential is not a proxy identity, and SOCKS5 never falls back to it — not even when nothing else is configured. An administrator who is also a directory user signs in with the directory password. |

A refused credential gets the RFC 1929 failure status. The reason is recorded,
not sent to the client:

- `invalid_credentials` — a directory provider is configured and did not accept
  the credential.
- `provider_not_supported_for_socks5` — no directory provider is configured, or
  the username's email domain routes to an OIDC/SAML profile.

The reason appears as the action of the `AUTH_FAIL` request-log entry, on the
`SOCKS5 AUTH_FAIL` log line, and in
`culvert_socks5_auth_failures_total{reason}` (present while the listener is
configured). A wrong password also counts toward the proxy authentication
failure total, as over HTTP.

Note: a gateway whose only accounts are admin-console accounts requires SOCKS5
username/password and refuses every SOCKS5 client. Add an LDAP profile, or
disable the listener.

## Choosing the policy mode

`proxy.socks5_policy_mode` in `config.yaml`, read at startup only:

| Value | Access policy (rules, categories, groups, geo, schedules, default action) |
|---|---|
| absent, `""` or `legacy` | Default. Not evaluated. No policy metrics or log lines. |
| `shadow` | Evaluated and recorded, **never enforced**: the connection is accepted or refused exactly as in `legacy`. Use it to see what `enforce` would do. |
| `enforce` | The verdict decides the connection (table below). |
| anything else | Rejected at startup. |

There is no admin UI or API switch for this setting (a recorded GUI-parity
deferral: like `socks5_port`, it is startup-only). Restart to change it.

**This setting is transitional.** The end state is SOCKS5 always enforcing
access policy, with no mode to choose. The removal plan, in order:

1. The SOCKS5 parity checks — the policy, threat-feed and identity differential
   tests against the HTTP/CONNECT engines, with their negative controls — and an
   end-to-end SOCKS5 verification pass on the main branch.
2. `enforce` becomes the default.
3. A later release deletes `legacy`, and then the setting itself once `shadow`
   is no longer needed.

Do not build automation that depends on `legacy`.

Downgrade note: configuration loading rejects unknown keys and values (contract
CFG-002). A release without this key refuses to start with it present, and a
release without `enforce` refuses that value. Remove the key before
downgrading.

## Enforce

| Policy outcome | SOCKS5 result | Request-log status |
|---|---|---|
| Allow rule | Connects (after the SSRF guard) | `OK`, rule name, `Allow` |
| Allow rule that requires TLS inspection | Reply `0x02` | `POLICY_BLOCK`, action `inspection_unsupported` |
| Drop | Connection reset, no reply | `POLICY_DROP` |
| Block_Page | Reply `0x02` | `POLICY_BLOCK` |
| Redirect | Reply `0x02` (a raw tunnel cannot be redirected) | `POLICY_REDIRECT` |
| Unrecognised action | Reply `0x02` (fails closed) | `POLICY_BLOCK` |
| No rule matched, default allow | Connects | `OK`, `default-allow` |
| No rule matched, default deny | Reply `0x02` | `POLICY_DEFAULT_DENY` |

`0x02` is the SOCKS5 reply "connection not allowed by ruleset". The evaluator,
the rulebase and the default action are the ones CONNECT uses; there is no
SOCKS5-specific default. With zero rules and no `default_action` the default is
allow; with any rule it is deny.

Enforce charges what a CONNECT charges: the rule's hit counter and last-hit
time, the rule-hit metric, the blocked counter, and one request-log entry per
decision with the rule name and ID, the identity and the authentication source.
A rule with "log traffic" off still counts an allowed connection without writing
a feed entry, as for CONNECT.

**TLS inspection is never silently skipped.** SOCKS5 has no inspection path.
An Allow rule with SSL action Inspect would give a CONNECT client an inspected
tunnel; a SOCKS5 client gets `0x02` instead, with reason
`inspection_unsupported` in the log and the metric. The only exceptions are the
ones that already turn a CONNECT inspection into a plain tunnel: a host on the
SSL bypass list, and a host a fail-open decryption profile has learned to
exclude. There is no SOCKS5-specific exception. If SOCKS5 clients must reach a
destination that your rules inspect, give them a rule with SSL action Bypass
(for example scoped by source or group).

Log line for a refusal (one per refused connection, like CONNECT):

```
SOCKS5 POLICY_BLOCK 192.0.2.10 -> "casino.example" {mode=enforce reason=rule rule="block-gambling" rule_id="…" action="Block_Page" identity=alice auth_source=local action_taken=Block_Page}
SOCKS5 POLICY_DEFAULT_DENY 192.0.2.10 -> "unlisted.example" {mode=enforce reason=default identity= auth_source=unauth action_taken=deny}
```

## Shadow

Shadow evaluates with the same evaluator and the same resolved identity as
enforce, but charges nothing: rule hit counters, "last hit" and the request log
are unchanged by it, and no connection is refused because of it.

Shadow predicts `inspection_unsupported` from the rule and the SSL bypass list
only. It does not read a fail-open profile's learned exclusions (reading them
would change their counters), so for such hosts it can report a refusal that
enforce would not make.

Log (sampled: at most one line per second; the counter is the exact total):

```
SOCKS5 POLICY_WOULD_BLOCK 192.0.2.10 -> "casino.example" {mode=shadow reason=rule rule="block-gambling" rule_id="…" action="Drop" identity=alice auth_source=local action_taken=none}
SOCKS5 POLICY_WOULD_BLOCK 192.0.2.10 -> "unlisted.example" {mode=shadow reason=default default_action=deny identity= auth_source=unauth action_taken=none}
```

## Metrics

Present in `shadow` and `enforce`, absent in `legacy`:

- `culvert_socks5_policy_decisions_total{mode,verdict,reason}` — `mode` is
  `shadow` or `enforce`; `verdict` is `allow`, or `would_block` (shadow) /
  `block` (enforce); `reason` is `rule`, `default` or `inspection_unsupported`.
- `culvert_socks5_requests_total{atyp="ipv4"|"ipv6"|"domain"}`, the address type
  the client sent. Clients that resolve DNS themselves send `ipv4`/`ipv6`. FQDN
  and category rules can't match those requests (the same as a CONNECT to an IP
  literal); source, identity, group, geo and schedule conditions still apply.

## Moving to enforce

1. Run `shadow` and watch `culvert_socks5_policy_decisions_total` and the
   `POLICY_WOULD_BLOCK` lines.
2. Expect `would_block` with `reason=default` for traffic no rule allows when the
   default action is deny, and `reason=inspection_unsupported` for destinations
   your Allow rules inspect. Add rules (for example an Allow + Bypass rule for the
   SOCKS5 clients that need those destinations) until the remaining refusals are
   ones you want.
3. Switch to `enforce` and restart.

## What changed from earlier releases

These changes are intentional. They apply whenever the SOCKS5 listener is on.

| Before | Now | Modes |
|---|---|---|
| A domain on the threat feed was served. | Refused with `0x02` and `THREAT_BLOCKED`, after the blocklist and before plugins. | all |
| The admin-console username and password authenticated SOCKS5, and were the only local SOCKS5 credential. | Never accepted. A gateway with only admin-console accounts refuses every SOCKS5 client. | all |
| SOCKS5 checked only the legacy provider or the admin account. Directory users in a registry LDAP profile could not sign in. | The shared resolver checks registry LDAP profiles, then a legacy LDAP provider. | all |
| An OIDC token sent as the SOCKS5 password was checked by a legacy OIDC provider. | Refused (`provider_not_supported_for_socks5`). | all |
| A gateway with an enabled identity-provider profile but no local account offered SOCKS5 without authentication. | Username/password is required. | all |
| SOCKS5 request-log entries had no user. | Entries after authentication carry the identity and `auth_source` (`unauth` without credentials); `AUTH_FAIL` carries the refusal reason. | all |
| Access policy was never evaluated. | Evaluated in `shadow` (recorded only) and `enforce` (decides). | shadow, enforce |
| — | An Allow rule that requires TLS inspection refuses the connection (`inspection_unsupported`). | enforce |
| `socks5_policy_mode: enforce` stopped startup. | Accepted. | — |

Unchanged: the listener stays off unless configured; the SSRF guard, admission
(IP filter, rate limit, connection limit), the startup posture gate, the
blocklist and plugins apply as before.

## See also

- [SOCKS5 listener health](socks5-listener-health.md)
- Contract SWG-901 in `contracts/registry.yaml`
