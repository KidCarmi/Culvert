# Proxy authentication posture — authentication never switches itself off

**Applies to:** every node that runs the HTTP proxy or the SOCKS5 listener.

**Owner decision "Durable Authentication Posture" (2026-11-23):** once proxy
authentication is established on a node, it cannot disappear silently. Only an
explicit, authorized policy decision — an `Exempt` authentication rule or the
`Exempt` default ("Open unmatched traffic") — admits traffic without
credentials. Contract `AUTH-006`; design record ADR-0063.

---

## 1. What it does

Before this release, whether proxy traffic had to authenticate depended on
whether an identity provider was *available right now*. A node with no
admin-console account whose last proxy identity provider was deleted, disabled
or failed to load was treated as "no authentication backend": every request
continued to Stage-2 policy as `unauth`, and SOCKS5 offered `NO-AUTH`.

Now each node keeps a small durable marker, **proxy authentication
established**. It is set the first time a proxy identity provider becomes
usable on the node and is never cleared by any normal operation. While it is
set:

| Node state | HTTP proxy | SOCKS5 |
|---|---|---|
| Fresh: proxy authentication never established, no provider | Unchanged: Stage 1 is skipped, requests continue to Stage 2 as `unauth` | Unchanged: `NO-AUTH` is offered and accepted |
| Established, a provider is usable | Unchanged | Unchanged |
| Established, **no usable provider** (deleted, disabled, failed to load, missing after a restart or a configuration change) | Every request that requires authentication gets a `407` that nothing can satisfy, with or without a presented credential — the same refusal as an admin-only installation (`AUTH_FAIL`) | `NO-AUTH` is never offered (a client that offers only `NO-AUTH` gets `0xFF`, no acceptable method); a client that offers username/password is refused with the RFC 1929 failure status, reason `auth_established_no_provider` |
| Established, no usable provider, and an `Exempt` rule or the `Exempt` default covers the request | Admitted without credentials exactly as on a node whose provider is still configured (`unauth` for the default, `exempt` for a scoped rule). A request that presents a credential is never exempted | SOCKS5 has no authentication rules and no `Exempt` default; it refuses |

"Usable provider" means an enabled LDAP, OIDC or SAML profile under
**Objects → Identity Providers** that loaded, or a legacy `ldap`/`oidc` block in
`config.yaml` that is wired. Admin-console accounts are never proxy identities
(owner Decision 2) and never establish or satisfy the posture.

Losing the provider is not a way to open the gateway. If some traffic must be
admitted without credentials, say so explicitly with a scoped `Exempt`
authentication rule or the `Exempt` default; see
[`authentication-rules.md`](authentication-rules.md).

## 2. What establishes it

The first successful activation of a proxy identity provider, through any of
these paths:

| Path | When the marker is written |
|---|---|
| Admin API / GUI: create a profile enabled, or enable / update an existing one (`POST /api/idp`, `PUT /api/idp/{id}`) | **Before** the profile is saved or used. If the marker cannot be written the change is refused with `500` and nothing changes |
| Control Plane → Data Plane configuration snapshot carrying an enabled profile | Before the snapshot's profiles are saved or used; if it cannot be written the snapshot is rejected and the next one retries |
| Control Plane → Data Plane configuration snapshot from an **established Control Plane** (`proxy_auth_established`), even with no provider left | Same as above. A Data Plane node that enrols after every provider was removed is established on its first snapshot, so it refuses instead of starting fresh |
| Startup: the IdP profile file loads an enabled profile, or a legacy `ldap`/`oidc` provider is wired | Immediately. If the write fails, the node is still treated as established for this run and the Diagnostics row says the marker is not durable |
| A profile that failed to load at startup recovers later (identity provider recovery) | As for startup |

Paths that do **not** establish it: storing a *disabled* profile (including the
explicit legacy-LDAP import, which always creates a disabled profile), config
import, and configuration-version rollback (neither carries identity
providers).

## 3. What never clears it

Nothing in normal operation lowers the posture:

- deleting or disabling every identity provider;
- a provider failing to load, at startup or later;
- a restart (the marker is a file in the data directory);
- a configuration-version rollback, including to a version that predates the
  provider — the marker is not part of the rollback surface and creates no
  configuration version;
- a config import;
- a later Control Plane snapshot with no identity provider, or with
  `proxy_auth_established` false or absent (the field only ever establishes);
- a backup restore. Backups include the marker (`data/proxy_auth_posture.json`).
  A restore **merges** it: if either the node being restored or the archive is
  established, the result is established. A restore can establish a node, never
  return it to fresh. A "fresh" record is never copied from an archive; the
  restored node re-evaluates at its next start (§4). A restore refuses to run if
  the node's current marker exists but cannot be read.

There is no API or GUI action that returns a node to the fresh state.

## 4. Upgrading, and a missing marker

The marker lives at `<data dir>/proxy_auth_posture.json`. When a node starts
and the file does not exist — the first start of this release, or a file
removed by hand — the node looks for evidence that proxy authentication was
configured before, once all configuration has loaded and before the proxy
listeners accept traffic:

- at least one identity provider profile stored in the registry, **enabled or
  not**;
- a legacy proxy provider wired from `config.yaml`;
- a legacy `ldap` block in `config.yaml`, wired or retired;
- the durable legacy-LDAP retirement record.

Any evidence establishes the posture (the marker records `migration: <what was
found>`). With none, the node is fresh, and a fresh record is written so the
check runs only once: a profile you later create *disabled* does not establish
the posture at the next restart; enabling it does.

**What this means at upgrade:** a node that has (or had, and still stores) an
identity provider profile starts established. If all its profiles are disabled,
or none loads, it refuses authentication-required traffic from the first start
of this release. Before upgrading such a node, either restore a working
provider, or add the `Exempt` rules or `Exempt` default for traffic that must
stay credential-free.

A marker that exists but is **corrupt** (not a record this release understands)
or **unreadable** (permissions, a directory in its place) is treated as
established — fail closed — and is left untouched for you to inspect.

An operator with host access can still delete the file. The next start then
re-derives the posture from the evidence above; on a node with no evidence that
returns it to fresh. Treat the file like the rest of the data directory.

## 5. Signals

- **Diagnostics** (`GET /api/diagnostics`, Support bundle): row
  `proxy_auth_posture`, present on every node and identical for every role (it
  names no account, roster fact or path):
  - `ok`: not established (fresh), or established (with since/by) and a provider
    is usable;
  - `warn`: established and a provider is usable, but the marker could not be
    written (held for this process only);
  - `fail`: established and no usable provider remains — authentication-required
    traffic is being refused — or the marker is corrupt/unreadable.
- **Kill switch row** (`auth_exempt_kill_switch`, only while the Authentication
  kill switch is engaged): on an established node with no provider it states
  that formerly exempt clients are refused, not that Stage 2 decides them.
- **Audit log:** `auth.proxy_posture.established` (actor `system`) once, when
  the posture is established. It is not a configuration change and creates no
  configuration version.
- **Logs:** `AuthPosture: ...` at startup and on establishment; a `WARN` for a
  corrupt/unreadable marker or a failed write.
- **Metric:** `culvert_socks5_auth_failures_total{reason="auth_established_no_provider"}`.

## 6. Returning to service after losing a provider

1. Restore a proxy identity provider: re-enable or repair the profile under
   **Identity Providers** (the startup log names a profile that failed to load),
   or create one.
2. Confirm the `proxy_auth_posture` row is `ok` and a test client authenticates.
3. If some clients must work without credentials meanwhile, add a scoped
   `Exempt` authentication rule for exactly those clients and destinations, and
   remove it afterwards.

## References

- Implementation: `internal/authposture` (the ratchet), `proxy_auth_posture.go`
  (activation hooks, migration, Diagnostics row), `proxy.go`
  (`resolveRequestAuth`, `requiredWithoutVerifier`), `socks5_auth.go`
  (`socks5AuthRequired`), `restore.go` (`stageProxyAuthPosture`).
- Tests: `proxy_auth_posture_test.go`, `internal/authposture/ratchet_test.go`.
- Contract: `AUTH-006` in `contracts/registry.yaml`. Decision record:
  [ADR-0063](../adr/0063-proxy-auth-posture-ratchet.md).
- Related: [`authentication-rules.md`](authentication-rules.md),
  [`authentication-kill-switch.md`](authentication-kill-switch.md),
  [`socks5-policy.md`](socks5-policy.md),
  [`identity-provider-revocation.md`](identity-provider-revocation.md).
