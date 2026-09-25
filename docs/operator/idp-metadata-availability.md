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
bytes.** For OIDC in particular, every discovered endpoint is put back through
the https/non-private check. A cache file edited on disk cannot widen anything.

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
2. Check `culvert_idp_metadata_last_success_timestamp_seconds` to see how much
   of that 7 days is left.
3. Fix egress to the IdP. Recovery is automatic and is declared only on an
   actual successful fetch.

### After a restore onto a fresh volume

The document cache lives under `<dataDir>/idp_metadata_cache/` and is *not*
authoritative state — it is a cache of a document your IdP publishes. A fresh
volume simply has no fallback until the first successful fetch, so make sure
egress to the IdP works before cutting traffic over. Deleting the directory is
safe at any time; it costs only the fallback.

## Known residual risks

* **A node that has never compiled a given profile has no fallback.** A
  first-ever enrollment, or a newly added IdP profile, still depends on
  reaching the IdP, and on that path a failure still rejects the whole IdP
  profile set in the config snapshot. Steady-state nodes are covered.
* **An IdP signing-key rotation during an outage is not picked up** until the
  IdP is reachable again. That is the intended trade: the alternative is to
  stop trusting a document the IdP has not actually retracted.
* **Metadata is only refreshed when a profile is compiled** (boot, admin save,
  config-version change). A long-lived process whose config never changes can
  hold a document for a long time and will not notice a rotation until
  something triggers a recompile. A periodic refresh is recorded as follow-up
  work (register row IDP-4).
