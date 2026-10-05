# Identity-provider revocation — what deleting or disabling an IdP cuts off

**Audience:** operators and incident responders.
**Scope:** the proxy data path's session identity (`ps_session`), not the admin
UI session (`ps_ui_session`), which is a separate cookie covered below.
**Engineering reference:** `roadmap/CHAOS-ENGINEERING-REVIEW.md` §41 (CHAOS-71),
register row **AU-2**.

---

## 1. What the lever does

Deleting an identity provider (`DELETE /api/idp/{id}`, or the **Remove** button
on **Identity Providers**) or disabling one (clearing **Enabled** on the
profile) is the appliance's revocation lever for a federation. You reach for it
when an IdP is compromised, when a partner's federation is being cut off, or
when a provider was configured by mistake.

As of this change it does **three** things, not one:

1. The provider stops authenticating new logins — it disappears from the IdP
   selection screen and the captive-portal redirect.
2. The provider stops validating presented credentials on
   `Proxy-Authorization: Basic` (this was already true).
3. **Sessions that provider already minted stop being identities.** A browser
   holding a `ps_session` cookie signed by this appliance and naming that
   provider is treated as if it had no cookie at all: it is re-challenged
   through the ordinary no-credential path (captive-portal redirect for a
   browser, `407` otherwise) and can log in again against whatever provider is
   still enabled.

**Item 3 is new.** Before it, a deleted or disabled provider's sessions kept
their subject **and the groups that provider asserted** for the remainder of the
session lifetime — up to 8 hours by default, up to 7 days if the session TTL was
raised. Those groups feed policy evaluation directly, so group-scoped **allow**
rules kept matching for a federation that had just been removed.

## 2. What it does *not* do

| Lever | Cuts proxy sessions? | Cuts admin-UI sessions? | Survives restart? | Reaches other cluster nodes? |
|---|---|---|---|---|
| Delete / disable an IdP | **Yes** (immediately) | n/a — the admin UI never issues an SSO cookie | **Yes** — derived from the stored profile set | **Yes** — via the `IdPProfiles` config snapshot |
| Delete a local admin account | n/a — a local login never mints a proxy cookie | Yes | **No** — the user revocation list is in memory only | **No** |
| Admin logout | Yes (that one token) | Yes (that one token) | Yes — the token revocation list is persisted | Yes — gossiped between nodes |

Two consequences worth knowing before an incident:

- **There is no "revoke this federated user" lever.** You can cut a whole
  federation, or you can wait out the session TTL for one user. Revoking a
  single SSO subject needs a product surface that does not exist yet.
- **Local account deletion does not survive a restart as a session revocation.**
  The account itself is durably gone and the admin UI refuses its sessions via
  the roster check, so this is not an exposure today — but do not rely on the
  user-level revocation list outliving a process.

## 3. Confirming the revocation reached live traffic

The refusal is deliberately indistinguishable, from the client's point of view,
from simply not having a cookie — that is what lets it reuse the existing
re-challenge path instead of inventing a second one. So it is invisible unless
you look at one of these:

| Surface | Where |
|---|---|
| **Identity Providers panel** | A banner appears above the provider list naming the number of requests re-challenged. |
| `GET /api/stats` | `sessionProviderRevoked` (viewer role). |
| `/metrics` | `culvert_session_provider_revoked_total` — always emitted; a flat `0` means nothing has carried such a session, never "the check is off". |
| Process log | `AUTH_SESSION_PROVIDER_REVOKED client=… provider=… identity=… total=…`, rate-limited to one line per minute with the cumulative count on every line. |

**Reading the number.** It counts **requests**, not distinct sessions: a browser
re-sends its dead cookie on every request until it re-authenticates. So:

- A **step up that then settles** right after you removed a provider is the
  expected shape — those are the sessions being cut, each client contributing a
  few requests before it logs in again.
- A count that **keeps climbing** hours later means clients are not completing
  re-authentication. Check that at least one interactive provider is still
  enabled, and that the captive-portal/SSO redirect resolves (Identity
  Providers → the remaining profiles; **Diagnostics** reports provider health).
- A **non-zero count with no recent IdP change** means something else removed a
  provider — a config import, a config-version rollback, or a Control Plane
  snapshot. Check the audit log for `idp.delete` / `idp.update` and the
  config-version history.

## 4. Recovery

There is nothing to undo. If a provider was removed by mistake, re-create or
re-enable it; new logins work immediately. Sessions cut in the meantime are
**not** restored — their holders simply log in again. No state is written by the
refusal, so there is no file to repair and no cache to clear.

If you removed the **only** interactive provider and no local admin account
exists, the proxy falls back to the global default authentication outcome. On a
`Default` posture that is a deny for unauthenticated traffic; see
`docs/operator/` on `defaultAuthOutcome` before removing the last provider on a
gateway that depends on SSO.

## 5. Why this is a state check and not a revocation list

Recorded here because it governs what you can rely on.

The revocation could have been implemented as an *event*: a `RevokeProvider`
entry pushed onto the session revocation list when an admin presses Delete.
It is implemented instead as a *state* check — on every request, "is this
provider still in the live set?" — for four operational reasons:

1. **The admin handler is not the only writer.** Config import, config-version
   rollback and the Control Plane's configuration snapshot all replace the
   provider set without going through it. An event emitted by the handler
   would miss all three; the state check covers them with no extra wiring.
2. **It needs no persistence of its own.** The provider set is already durable
   (`idp_profiles.json`), so the revocation survives restart because the
   *absence* does.
3. **It needs no gossip.** `ConfigSnapshot.IdPProfiles` already carries the
   provider set to every Data Plane node, so a Control Plane deletion reaches
   the fleet on the next sync with nothing new to replicate.
4. **It cannot go stale or be evicted.** A revocation-list entry has an expiry
   and a cap; a derived check is re-evaluated on every request and is correct
   for as long as the provider is absent.

The practical upshot: **restoring a backup that still contains the provider
restores its ability to authenticate.** If you remove a provider as an incident
response, make sure the change is captured in your configuration baseline, or a
later rollback will quietly re-enable it.
