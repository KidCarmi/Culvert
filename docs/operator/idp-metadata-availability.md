# IdP metadata and discovery availability (CHAOS-71)

Applies to interactive identity providers — SAML profiles with a
`metadataUrl`, and OIDC profiles (which fetch
`<issuer>/.well-known/openid-configuration`). Profiles whose SAML metadata is
pasted inline (`metadataXml`) never touch the network and are unaffected by
everything on this page.

## What changed and why

Compiling an enabled SAML or OIDC profile performs an outbound fetch against
your identity provider. That fetch runs on three paths that must not depend on
a third party: appliance boot, the admin save path, and — the one that caused
the most damage — **every Control Plane → Data Plane config sync**.

Before this change the fetch had no cache and no fallback, so:

* an IdP that was briefly unreachable **at boot** left the profile enabled,
  stored, listed in the admin UI, and unable to authenticate anybody, with no
  metric, no health row and no alert — recoverable only by restarting the
  appliance or re-saving the profile;
* an IdP maintenance window **stopped policy, blocklist and threat-feed
  distribution to every data plane in the fleet**, because a failed IdP compile
  aborted the whole config snapshot; and
* because the config version could not advance, every data plane retried the
  whole apply — fetch included — every 30 seconds for the duration of the
  outage, aiming the fleet's full poll rate at the IdP that was already down.

Now the appliance keeps the **last document it successfully fetched** and
degrades to it when the IdP is unreachable.

## The rules that govern it

**The network always wins when it answers.** The cache is a fallback, never a
first choice, so an IdP-side signing-key rotation is picked up at the first
compile after it happens, exactly as before.

**A cached document is refused once it is older than 7 days.** Withdrawing a
key from published metadata is your IdP's revocation lever; serving a cached
document forever would keep trusting a key your IdP has retired. Past the
ceiling the compile fails exactly as it did before this change. The ceiling is
a constant with no configuration knob — the only thing a knob here could do is
widen the window in which a withdrawn key stays trusted.

**A cached document is bound to its source.** Re-pointing a profile at a
different metadata URL or issuer has no cache, so a migration can never be
answered by the provider you are migrating away from.

**Cached bytes are parsed and validated by exactly the same code as network
bytes.** For OIDC, all three endpoints the appliance uses from the document
(authorization, token, JWKS) are re-checked STRUCTURALLY — absolute, `http` or
`https`, host present, and not a private IP literal — so a cache file edited on
disk cannot widen the shape of what is accepted.

The address check is deliberately split, because the two kinds of endpoint have
different protections. The token and JWKS endpoints are ones the appliance
**dials**, and every such dial goes out through the SSRF-guarded dialer, which
refuses a private *resolved* address at connect time and is immune to DNS
rebinding — so a structural check is sufficient there, and a resolving check
would make the cache unusable during exactly the outage it exists for. The
authorization endpoint is **not dialled by the appliance at all** — it is handed
to the user's browser — so no dialer is ever consulted, and it therefore keeps
its own resolving check at compile time. That check refuses only a DEFINITE
private verdict: a name that cannot be resolved is treated as *unknown*, not
*private*, so a resolver outage can never reject a cached document.

**The degradation alert does not depend on another fetch.** A provider serving from cache is still *live*, so nothing recompiles it and the dark-provider recovery loop does not cover it. A separate detection-only watchdog therefore evaluates open episodes against the clock and fires the page once the threshold is crossed, even if no further fetch is ever attempted. It never fetches, never compiles and never clears an episode — recovery still requires observed evidence — and it does not run at all on a node with no enabled remote-metadata profile.

**A dark provider recovers on its own.** If a profile still cannot be compiled
— unreachable at boot with nothing cached — the appliance retries at a bounded
rate (2 s, doubling to 5 minutes, jittered) until it succeeds. No restart is
needed. Retries are unbounded in count and bounded in rate, and are never
silent.

## Where to look

**Diagnostics** — the `idp_metadata` row on `/api/diagnostics`:

| State | Severity | Meaning |
|---|---|---|
| No remote IdP metadata/discovery documents in use | ok | Nothing to report on this node. |
| *N* of *M* enabled interactive IdP profile(s) have NO live provider | **warn** | **Browser SSO is not working for those profiles.** This is the state that had no surface at all before CHAOS-71. |
| IdP metadata/discovery fetches have been failing for *D* | warn | Authentication still works from cached documents; IdP-side changes are not being picked up. |
| IdP metadata/discovery healthy | ok | Carries cumulative counts so past transient outages stay visible. |

**Metrics** — emitted only on a node that has an enabled interactive IdP
profile or has fetched a remote document. A node that never configured SSO
emits nothing here, deliberately: a flat `0` from every such appliance would be
indistinguishable from one whose IdP is dead.

| Series | Page on |
|---|---|
| `culvert_idp_enabled_not_live` | **`> 0`** — an enabled IdP profile cannot authenticate anybody. |
| `culvert_idp_metadata_degraded` | `== 1` — sustained fetch failures; softer, earlier warning. |
| `culvert_idp_metadata_stale_served_total` | Rising — compiles are running from cached documents. |
| `culvert_idp_metadata_unavailable_total` | Rising — unreachable **and** no usable cache: this is the state that leaves providers dark. |
| `culvert_idp_metadata_fetch_failures_total` | Trend only. |
| `culvert_idp_metadata_cached_documents` | Fallback coverage. Zero here means a future outage has no fallback. |
| `culvert_idp_authz_endpoint_unverified_total` | **Rising** — an OIDC authorization endpoint was admitted without a public-address verdict and is being handed to browsers unverified. Almost always this node's resolver; see the residual below. |
| `culvert_idp_metadata_last_success_timestamp_seconds` | Age against the 7-day ceiling. |

**Alerts** — the existing `identity_backend_unreachable` event, source
`idp_metadata`, fired once per degradation episode and re-armed by an observed
successful fetch. It reuses the existing event name on purpose: a new name
would be silently unsubscribed on every webhook you have already configured,
and "the IdP cannot be reached" is one operator action whether the unreachable
thing is an LDAP bind endpoint, an OIDC introspection endpoint, or the metadata
document.

**Logs** — `IDP_METADATA_FETCH_FAILED` (rate-limited to one line per 5 minutes,
carrying the suppressed count and the underlying cause),
`IDP_METADATA_RECOVERED`, and `IDP_RECOVERED` when a dark provider goes live.

## Not on `/readyz`, deliberately

An IdP outage is fleet-wide by construction — every node talks to the same IdP
— so failing readiness would eject the entire fleet from the load balancer
simultaneously over a dependency none of them can fix by restarting, turning an
SSO degradation into a total traffic outage. Traffic is still being proxied
throughout. This follows the same rule as the `ca`, `cluster_ca` and
`dns_resolution` rows.

## Runbook

### `culvert_idp_enabled_not_live > 0`

Browser SSO is unavailable for those profiles right now. Users matched by an
`SSORequired` rule receive `403 Forbidden: destination requires interactive
SSO`; unmatched traffic falls through to Stage-2 policy, where default-deny
still applies.

1. Check this node's egress to the IdP metadata URL / issuer. This is almost
   always a network or DNS problem on the appliance side, not an IdP problem.
2. Check `culvert_idp_metadata_unavailable_total` — if it is rising, the node
   is reaching the compile path and failing the fetch, which confirms (1).
3. **Do not restart to recover.** The appliance already retries on its own and
   the provider goes live on the first successful fetch. A restart only helps
   if the profile has never compiled on this node and you have just fixed the
   network, and even then the retry loop will get there first.
4. If the fetch succeeds by hand (`curl` from the appliance) but the provider
   stays dark, the document itself is being rejected — look for the
   `IdP "<id>" compile error` line, which carries the parser's reason.

### `culvert_idp_metadata_degraded == 1`

Providers are running from cached documents. Nobody is locked out **yet**.

1. This is your warning window. Two things are true while it lasts: an
   IdP-side signing-key rotation will not be picked up, and each cached
   document stops being usable 7 days after it was fetched, after which browser
   SSO stops.

   That 7-day ceiling is **enforced on a running appliance**, not only when a
   profile is next compiled. A background check retires a provider whose served
   document has expired: it logs `IDP_METADATA_EXPIRED`, stops serving that
   provider (so browser SSO for it fails closed rather than trusting a signing
   certificate your IdP may have withdrawn), and hands it to the retry loop,
   which brings it back automatically the moment a document is fetched
   successfully. Your profile is left **enabled and stored** throughout — the
   configuration is still correct, it is the cached document that expired, so
   there is nothing to re-enter and nothing to re-create.

   A provider that is serving a **freshly fetched** document is never retired,
   however old the cached copy beside it is.
2. Check `culvert_idp_metadata_last_success_timestamp_seconds` to see how much
   of that 7 days is left.
3. Fix egress to the IdP. Recovery is automatic and is declared only on an
   actual successful fetch.

There are two other ways the gauge clears, and they are the only cases where no
fetch is involved. Both apply the same rule — an episode describes a failed
fetch against a **source**, so it is closed when that source stops being
something this appliance fetches — and both take effect only once the change has
been **saved**, never while an edit is merely being validated:

* Switching that profile from a remote `metadataUrl` to inline `metadataXml`
  (or disabling it, or deleting it) leaves no remote fetch to recover, so the
  episode is closed and one `IDP_METADATA_RECOVERED` line is logged.
* **Re-pointing a profile from one remote source to another** closes the OLD
  source's episode. This is what you do when an IdP URL changes or you migrate
  providers, and it is the case that used to alert forever: nothing fetches the
  old URL any more, so nothing could ever produce the evidence to clear it.

In both cases other profiles' episodes are untouched — including another
profile pointing at the same URL — and no attempt is counted. If the edit is
**rejected** (the new source cannot be compiled, or the change cannot be
persisted) the old configuration stays in service and its episode stays open,
because it is still describing a live outage.

A DNS failure at the IdP's host reaches this gauge rather than refusing the
config: an unresolvable IdP hostname is a *resolution* failure, so it fails the
fetch and falls back to the cached document. A **configuration** error — a
non-absolute URL, a scheme other than http/https, or a private IP literal — is
rejected outright at compile time and is never answered from cache.

So does a document the appliance **cannot accept**. If your IdP starts serving
an OIDC discovery document that this appliance refuses — most realistically one
whose `authorization_endpoint` resolves into a private range, which would
redirect your users' browsers into the internal network — that is treated as an
availability failure, not as a new document: the previously cached document
keeps serving, the gauge goes to 1, and the refused document's cause appears in
the `IDP_METADATA_FETCH_FAILED` line with `outcome="stale_cached"`. The refused
document never replaces your last-known-good copy, so the fallback survives the
episode. With **nothing** cached there is no fallback and the provider fails to
compile, which is the correct fail-closed outcome — look for the same cause in
the log and check what your IdP is publishing.

### After a restore onto a fresh volume

The document cache lives under `<dataDir>/idp_metadata_cache/` and is *not*
authoritative state — it is a cache of a document your IdP publishes. A fresh
volume simply has no fallback until the first successful fetch, so make sure
egress to the IdP works before cutting traffic over. Deleting the directory is
safe at any time; it costs only the fallback.

## Known residual risks

* **An unverifiable authorization endpoint is admitted, not refused** (register
  row IDP-9). The OIDC `authorization_endpoint` is the one discovered endpoint
  this appliance never dials — it is handed to the user's browser — so the
  SSRF-guarded dialer does not cover it, and the redirect validator checks only
  URL shape. It is address-checked when the discovery document is parsed, but
  that check refuses only a **definite** private verdict: if the address cannot
  be determined at all (this node's resolver is down, or the check's own budget
  is spent) the endpoint is admitted unverified, and nothing re-checks a
  provider that is already live. A host that is unresolvable at compile time
  and later resolves to a private address would therefore be a browser redirect
  into your internal network.

  Refusing instead would take SSO down whenever *this node* cannot resolve the
  authorization host — even though the user's browser can — and would let a
  resolver outage reject a cached document, which is the whole failure this
  page exists to prevent. So the trade is deliberate and it is visible:
  `culvert_idp_authz_endpoint_unverified_total` rising, plus one
  `IDP_AUTHZ_ENDPOINT_UNVERIFIED` log line per minute naming the profile.
  **If you see it: fix this node's DNS.** A provider compiled while the
  resolver was healthy carries a verified endpoint.

* **A node that has never compiled a given profile has no fallback.** A
  first-ever enrollment, or a newly added IdP profile, still depends on
  reaching the IdP, and on that path a failure still rejects the whole IdP
  profile set in the config snapshot. Steady-state nodes are covered.
* **An IdP signing-key rotation during an outage is not picked up** until the
  IdP is reachable again. That is the intended trade: the alternative is to
  stop trusting a document the IdP has not actually retracted.
* **Two discovery endpoints are not in the validation loop** (register row
  IDP-8): `userinfo_endpoint` and `introspection_endpoint` are taken from the
  document and dialled with a bearer token and the client secret respectively,
  without being re-checked. The SSRF-guarded dialer still applies, so they
  cannot reach a private address, but nothing refuses a plain-`http` endpoint
  there — a discovery document that downgraded one would send credentials in
  cleartext to a public host. Refusing non-`https` for those two is a posture
  change with its own compatibility cost and is recorded as follow-up work.
* **Metadata is only refreshed when a profile is compiled** (boot, admin save,
  config-version change). A long-lived process whose config never changes can
  hold a document for a long time and will not notice a rotation until
  something triggers a recompile. A periodic refresh is recorded as follow-up
  work (register row IDP-4).
