# SOCKS5 policy shadow mode (SWG-901 stage 2)

SOCKS5 does not apply Stage-2 access policy today: rules, categories, groups,
geo, schedules and the default action are enforced for HTTP and CONNECT only
(contract SWG-901, open). The owner has decided SOCKS5 belongs inside the
managed boundary, in stages. This page covers stage 2: **observe, never
enforce**.

## Turning it on

`proxy.socks5_policy_mode` in `config.yaml`, read at startup only:

| Value | Behaviour |
|---|---|
| absent, `""` or `legacy` | Default. No policy evaluation, no new metrics, no new log lines. Identical to previous releases. |
| `shadow` | Every SOCKS5 CONNECT that passes the existing gates is evaluated against Stage-2 policy and the result is recorded. **The connection is still accepted or refused exactly as in `legacy`.** |
| `enforce` | Rejected at startup: not available yet (stage 4). |
| anything else | Rejected at startup. |

There is no admin UI or API switch for this setting (a recorded GUI-parity
deferral: like `socks5_port`, it is startup-only). Restart to change it.

Downgrade note: configuration loading rejects unknown keys (contract CFG-002),
so a release without this key refuses to start with it present. Remove the key
before downgrading.

## What shadow mode records

The evaluation runs after the blocklist and plugin checks and before the SSRF
guard and dial, which is where enforcement would sit. It uses the same policy
evaluator, rulebase and default action as CONNECT, but charges nothing: rule
hit counters, "last hit" and the request log are unchanged by it.

Metrics (present only in `shadow` mode, absent in `legacy`):

- `culvert_socks5_policy_decisions_total{mode="shadow",verdict="allow"|"would_block",reason="rule"|"default"}`.
  `would_block` means the CONNECT path would have refused the same destination
  (Drop, Block_Page, Redirect, an unrecognised action, or the default action
  denying an unmatched destination).
- `culvert_socks5_requests_total{atyp="ipv4"|"ipv6"|"domain"}`, the address type
  the client sent. Clients that resolve DNS themselves send `ipv4`/`ipv6`. FQDN
  and category rules can't match those requests (the same as a CONNECT to an IP
  literal).

Log (sampled: at most one line per second; the counter is the exact total):

```
SOCKS5 POLICY_WOULD_BLOCK 192.0.2.10 -> "casino.example" {mode=shadow reason=rule rule="block-gambling" rule_id="…" action="Drop" auth_source=unauth action_taken=none}
SOCKS5 POLICY_WOULD_BLOCK 192.0.2.10 -> "unlisted.example" {mode=shadow reason=default default_action=deny auth_source=unauth action_taken=none}
```

No new request-log status is written in shadow mode.

## Limitation: no identity yet

SOCKS5 does not resolve a user identity until stage 3. Its username/password
check only answers yes or no. Every shadow evaluation therefore runs as an
**unauthenticated** client (`auth_source=unauth`, no identity, no groups),
including clients that did authenticate with a username and password. As a
result:

- rules scoped to a user, group or identity provider never match SOCKS5 traffic
  in shadow mode;
- rules scoped to `unauth` match every SOCKS5 client.

With a default-deny policy whose Allow rules are group-based, expect most
SOCKS5 traffic to show as `would_block` with `reason=default`. That is a true
statement about what enforcement would do **today**. It is not a measurement of
what enforcement will do after stage 3. Source-IP, destination, category, geo
and schedule conditions are evaluated as for CONNECT.

## See also

- [SOCKS5 listener health](socks5-listener-health.md)
- Contract SWG-901 in `contracts/registry.yaml`
