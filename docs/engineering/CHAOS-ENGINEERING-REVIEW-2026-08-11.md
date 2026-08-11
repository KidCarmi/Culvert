# Chaos Engineering Review — 2026-08-11

**Domain:** the multi-IdP **registry** authentication path (`auth_oidc_flow.go`) under
identity-provider failure — JWKS key distribution, RFC 7662 introspection, and the
per-request dispatch loop that fans a single credential across every enabled provider.
**Register items:** **CHAOS-49** (open since 2026-08-03, marked "next run's top candidate")
· adds and closes three previously unrecorded defects in the JWKS cache.
**Verdict:** six confirmed defects, all fixed, every one reproduced empirically against
`main` before the fix was written.

---

## Executive Summary

CHAOS-47 (2026-08-03) hardened the **legacy** single-provider identity backends — LDAP and
`auth_oidc.go` — with a three-part contract: an infrastructure failure is never cached as a
verdict about a credential, an unreachable backend arms a half-open probe gate so an outage
costs one round trip instead of one per request, and both facts are reported on the
`identity_backend` operator-contract row. That review closed by naming the surviving half of
the problem: the **newer IdP-registry path has none of it**, and recorded it as CHAOS-49.

This sweep confirms CHAOS-49 is live on `main` and found that the domain is worse than
recorded in three ways that have nothing to do with introspection at all. The JWKS cache —
the component that distributes the *public keys every ID-token validation depends on* —
has a corruption bug, an amplification bug, and a thundering-herd bug, all three reachable
from ordinary traffic and two of them reachable **without any credential**.

| # | Failure mode | Class | Why the existing design did not cover it |
|---|---|---|---|
| 1 | An HTTP 200 carrying no usable keys **wipes the key cache** | State corruption → total SSO outage | `refresh()` installed whatever it parsed; "no keys" and "no *usable* keys" were indistinguishable from a valid empty set |
| 2 | A **non-200** response is decoded and installed as a key set | State corruption | `resp.StatusCode` was never checked; a JSON error body behind a 503 parses cleanly into `jwkSet{}` |
| 3 | An **unknown `kid` re-fetches the JWKS on every request** | Unauthenticated amplification against the customer's IdP | the refetch decision keyed on cache *membership*; a miss is permanent for a kid that will never be there |
| 4 | Concurrent misses produce **N concurrent fetches** | Thundering herd | no single-flight |
| 5 | Introspection has **no result cache** | Latency + IdP load, per request per provider | CHAOS-49 as recorded |
| 6 | An unreachable IdP costs a **full dial timeout per request, per provider**, and is invisible | Recovery failure + silent failure | CHAOS-49 as recorded — no probe gate, no health reporting, infra failure indistinguishable from "token invalid" |

Defects 1 and 2 are the most serious finding in this review and were **not** in the register.
They are a *silent, self-inflicted, fleet-wide outage of browser SSO* triggered by a transient
IdP misbehaviour, and — this is the part that matters — they destroy the very mechanism the
code has for surviving that misbehaviour. `getKey` contains an explicit fallback:

```go
if err := j.refresh(); err != nil {
    if ok {
        return k, nil // return stale key rather than failing
    }
```

That fallback is unreachable after a wipe, because the wipe happens on the *success* path.
The IdP returns one bad-but-parseable 200, every cached key is deleted, and from then on
there is no stale key left to fall back to. Every subsequent validation fails with
`jwks: key "..." not found` for as long as the endpoint stays degraded, with no log line,
no metric, and no health signal anywhere in the process.

Defect 3 is the one an attacker reaches. The `kid` is read from the **unverified** header of
a token supplied in `Proxy-Authorization`, so it is entirely caller-controlled and needs no
valid credential. Pre-fix, one such request produced one outbound JWKS `GET` — per
configured provider, forever, with no ceiling. That is a request-rate-to-IdP-load amplifier
pointed at the customer's own identity infrastructure, and defect 4 means a burst arrives at
the IdP as a burst.

Defect 3 also fires **without an attacker**, on the most ordinary multi-IdP deployment there
is. The dispatch loop in `proxy.go` asks *every* enabled provider about the same credential:

```go
for _, prov := range idpRegistry.EnabledProviders() {
    id, resolved := prov.ResolveIdentity(u, p)
```

so with two IdPs configured, provider A is asked about provider B's token on every single
request. B's token is a well-formed JWT with a `kid` A has never heard of — the exact miss
shape. Two IdPs, and half of all authenticated traffic became a JWKS fetch storm against
each of them.

### Measured, against `main`

A temporary proof harness (`TestProof_*`, removed before commit) was run against the
unmodified engine. Every defect reproduced on the first attempt:

| Proof | Result on `main` |
|---|---|
| FS-1 empty key set after a good fetch | `jwks: key "kid-1" not found` — **cache wiped** |
| FS-2 HTTP 503 with a JSON body | `jwks: key "kid-1" not found` — **503 body installed as the key set** |
| FS-3 50 unknown-kid lookups | **50 JWKS fetches** |
| FS-3b 40 concurrent misses | **40 JWKS fetches** |
| FS-4 20 authenticated requests, healthy IdP | **20 introspection round trips** |
| FS-4b 11 requests, IdP down | **11 round trips**; `degraded=false`, `gatedDenials=0`, `unavailable=0` |

The last row is the whole of CHAOS-49 in one line: eleven full failures against a dead IdP,
and the appliance's own identity-backend health reports nothing at all.

---

## Failure Scenarios

### FS-1 — A degraded IdP response destroys the key cache

**Current behavior (pre-fix).** `jwksCache.refresh()` decoded the body, built a `keys` map
from every RSA entry it recognised, and installed it unconditionally:

```go
j.mu.Lock()
j.keys = keys        // <- whatever we just parsed, including an empty map
j.fetchedAt = time.Now()
j.mu.Unlock()
```

Three realistic responses produce an empty `keys` map from a **200**:

- an edge/rate-limiter body (`{"error":"rate_limited"}`, `{}`) — decodes into `jwkSet{}`;
- an IdP that has rotated entirely to EC keys — every entry hits `if kh.Kty != "RSA" { continue }`;
- a JWKS behind a captive proxy or a misrouted CDN returning a stub document.

**Expected behavior.** A response carrying no usable key is evidence that something is wrong
with the *response*, not evidence that the IdP has no keys. Keep the last known-good set,
fail the individual lookup closed, and say so.

**Failure mode.** Total, silent, fleet-wide failure of ID-token validation — every browser
SSO session and every JWT presented on the proxy-auth path — persisting until a good refresh
lands. Because `fetchedAt` was advanced by the bad refresh, the next attempt does not come
for up to 15 minutes; and each attempt that returns the same degraded body re-wipes.

**Monitoring visibility (pre-fix).** None. `refresh()`'s error was already discarded by
`getKey`'s stale-key fallback, and the wipe path *is not an error* — it is the success path.

**Post-fix.** `refresh()` returns an error rather than installing an empty set, the cached
keys survive, the stale-key fallback works as designed, and a rate-limited line names the
endpoint and the reason.

### FS-2 — An HTTP 503 is parsed as a key set

`refresh()` never looked at `resp.StatusCode`. Any error body that happens to be JSON —
which is most modern IdPs' error format — decoded cleanly into `jwkSet{Keys:nil}` and took
the FS-1 wipe path. A 500 whose body is HTML failed to decode and was therefore *safer* than
a well-behaved JSON 503. Post-fix, a non-200 short-circuits before the decoder.

### FS-3 — Unknown `kid` amplification (unauthenticated)

**Current behavior (pre-fix).**

```go
k, ok := j.keys[kid]
stale := time.Since(j.fetchedAt) > jwksCacheTTL
if ok && !stale { return k, nil }
if err := j.refresh(); err != nil { ... }
```

For a kid that is not in the set, `ok` is false regardless of freshness, so **every call
refreshes**, and the refresh succeeds (the key set is fine — the kid simply is not in it),
so nothing ever backs off.

**Trigger, ranked by likelihood:**

1. *Normal multi-IdP operation.* The registry loop asks provider A about provider B's token.
2. *A rotated-out kid.* A client holding a token signed by a retired key.
3. *An attacker.* `Proxy-Authorization: Basic base64(u:<JWT with a random kid>)`, one
   outbound GET per request per provider, no credential required.

**Failure mode.** Two, compounding. Outbound: the gateway becomes a DoS amplifier aimed at
the customer's IdP, with gain = (number of configured providers). Inbound: every affected
request pays a full JWKS round trip inside the auth path, holding a request goroutine.

**Post-fix.** `lastAttempt` bounds the refresh *rate* (`jwksMinRefreshInterval`, 1 min)
independently of cache membership. A kid that will never be present costs at most one fetch
per minute per provider instead of one per request. Freshness is unaffected: the interval is
15× shorter than `jwksCacheTTL`, so a genuine rotation is still picked up promptly — pinned
by `TestJWKS_StaleCacheStillRefreshesAfterNegativeWindow`, which fails if the negative window
is ever allowed to freeze the cache.

### FS-4 — No single-flight

40 concurrent misses produced 40 concurrent fetches. This is the reconnect-storm shape: a
fleet of clients reconnecting after a network blip all present the same token at the same
instant. Post-fix, one leader fetches, followers wait and share its outcome (including its
error, so a failure produces one diagnosable reason rather than N `key not found`s).

### FS-5 / FS-6 — CHAOS-49: introspection has no cache, no gate, no voice

**Current behavior (pre-fix).** `OIDCFlowProvider.introspect` returned `(nil, false)` for
every failure — dial refused, TLS error, HTTP 500, malformed body, *and* a legitimate
`active:false`. It had no cache, so every request re-introspected; no gate, so every request
against a down IdP paid the full 10 s ceiling; and no reporting, so the outage never reached
the `identity_backend` row, `culvert_auth_backend_*`, or the
`identity_backend_unreachable` alert.

**The multiplier is the dispatch loop.** Providers are tried **sequentially**. With three
IdPs configured and the estate's IdP down, a single proxied request costs up to **30 s** of
serialized dial timeouts before it 407s — with the request goroutine, its connection, and its
per-IP connection slot all held for the duration. Under any real request rate that is a
goroutine and connection-slot exhaustion path, and it converts an IdP outage into a gateway
outage.

**Post-fix.** The provider gets the exact CHAOS-47 contract, reusing the same primitives
(`authProbeGate`, `noteAuthBackend*`, `cacheKey`, `cloneIdentity`, `maxAuthCacheSize`,
`errIntrospectClient`) rather than a parallel implementation:

- **Result cache** keyed by `cacheKey("", token)` — an HMAC, so no bearer token is held in
  the map — bounded by `maxAuthCacheSize`, TTL 2 min, and **clamped to the token's own
  declared `exp`** so a cached "yes" can never outlive the credential it came from.
- **Probe gate.** An unreachable IdP arms a 3 s cooldown; requests inside it are denied
  without a round trip and counted as `gatedDenials`. This is what collapses N × 10 s back
  to a constant.
- **Infrastructure failure is never cached.** Only an authoritative answer from a reachable
  endpoint — `active:false`, wrong scope, wrong audience, no subject — enters the cache.
  Recovery is bounded by the 3 s cooldown, not by the 2 min TTL, and is driven by evidence:
  one observed reach clears the gate for every caller.
- **A 4xx is not an outage.** It denies the request, does **not** arm the provider-wide
  gate — otherwise one caller with a malformed token locks out every other user — and, because
  the endpoint demonstrably answered, it **clears** any cooldown a previous outage armed.
  (Without that clear, a 4xx silently eats each half-open probe and the gate re-arms behind
  it, holding a recovered IdP in a permanent outage. The same defect was found and fixed on
  the LDAP and legacy-OIDC legs in CHAOS-47; it would have been reintroduced here verbatim.)

---

## Risk Matrix

| ID | Failure mode | Likelihood | Impact | Priority | Status |
|---|---|---|---|---|---|
| FS-1 | Degraded 200 wipes the JWKS cache | Medium | **High** — silent fleet-wide SSO outage | P1 | **FIXED** |
| FS-2 | Non-200 installed as a key set | Medium | **High** — same | P1 | **FIXED** |
| FS-3 | Unknown-kid amplification | **High** (normal in any 2-IdP estate) | High — IdP DoS + per-request latency | P1 | **FIXED** |
| FS-4 | No single-flight on refresh | Medium | Medium — burst amplification | P2 | **FIXED** |
| FS-5 | No introspection cache | **High** (every request) | Medium — latency + IdP load | P2 | **FIXED** |
| FS-6 | No probe gate / no health reporting | Medium | **High** — N × 10 s per request, invisible | P1 | **FIXED** |

---

## Recovery Assessment

| Scenario | Pre-fix recovery | Post-fix recovery |
|---|---|---|
| IdP JWKS returns a degraded 200 | **None automatic.** Cache stays wiped; a restart does not help while the endpoint is degraded | Automatic — cached keys are retained and served; validation resumes the moment a good key set lands |
| IdP introspection unreachable | Automatic but **expensive** — every request pays the full timeout for the whole outage | Automatic and **cheap** — one probe per 3 s cooldown; one observed reach releases every caller |
| IdP recovers after a blip | Immediate (nothing was cached) but the blip cost N × 10 s per request while it lasted | Immediate; cost during the blip is bounded by the gate |
| Unknown-kid flood | None — unbounded for as long as the traffic continues | Automatic — bounded to one fetch/minute/provider regardless of request rate |

Manual recovery is required in exactly one place, unchanged by this work: an IdP that has
rotated to key types this build cannot parse (EC/ES256 in a JWKS with no RSA entry) needs
operator action. The difference is that it is now a **logged, non-destructive** failure that
keeps serving the last good keys, instead of a silent wipe.

---

## Operational Impact

Everything new rides surfaces that already exist, so there is no new operator vocabulary and
no new configuration:

| Surface | Signal | Change |
|---|---|---|
| `/api/diagnostics` | `identity_backend` operator-contract row | now covers registry IdPs; backend reads `oidc:<profile-id>` |
| `/metrics` | `culvert_auth_backend_unavailable{,_total}`, `culvert_auth_backend_gated_denials_total` | now move for registry IdPs |
| Alerts | `identity_backend_unreachable` | now fires for registry IdPs (`HasSubscriber`-gated, 5 min rate-limited) |
| Logs | `OIDC[<id>] auth UNAVAILABLE …`, `OIDC[<id>] auth DENY (introspection 4xx) …`, `OIDC: JWKS refresh FAILED for … — serving previously cached keys` | new; the JWKS line is rate-limited to one per minute per cache |

**GUI parity:** no new CLI flag, YAML key, or admin API field is introduced, so the parity
rule is satisfied by the existing panels — the `identity_backend` row, the metrics, and the
alert are already surfaced. This is deliberate: the cheapest correct fix here was to make the
new backend speak the vocabulary the old one already established, not to invent a second one.

---

## Security Impact

- **Availability of a security control.** ID-token validation is an authentication control;
  FS-1/FS-2 took it out silently. The fix is fail-closed per lookup and non-destructive to
  shared state — the posture the register's §1 theme demands.
- **Unauthenticated amplification removed.** FS-3 let anyone who can reach the proxy port
  turn request rate into load on the customer's IdP, with no credential and no ceiling.
- **No new credential exposure.** Cache keys are HMAC tags (`cacheKey`), so bearer tokens are
  never held in the map — the same property the legacy backend relies on.
- **Cache introduces a bounded revocation delay** (see Residual Risk).
- **The 4xx carve-out is a denial-of-service fix, not a weakening**: without it, an
  unauthenticated caller can hold a *healthy* IdP in a permanent gated outage for every other
  user by replaying one malformed token.

## Data Integrity Impact

FS-1/FS-2 are the only state-corruption findings, and the corrupted state is in-memory and
non-persistent — no on-disk artefact is affected, and a restart re-fetches. The fix makes the
key set replaceable only by a response that is both HTTP 200 and carries at least one usable
key.

---

## Required Tests

All in `auth_oidc_flow_chaos_test.go`, and all corresponding to a proof that reproduced on
`main`:

| Test | Pins |
|---|---|
| `TestJWKS_EmptyKeySetDoesNotWipeCachedKeys` | FS-1 — a 200 with no usable keys must not destroy the cache |
| `TestJWKS_NonOKStatusDoesNotWipeCachedKeys` | FS-2 — a non-200 is never a key set |
| `TestJWKS_UnknownKidDoesNotRefetchPerCall` | FS-3 — 50 unknown-kid lookups ⇒ ≤1 fetch |
| `TestJWKS_ConcurrentMissesCoalesceIntoOneFetch` | FS-4 — 40 concurrent misses ⇒ exactly 1 fetch |
| `TestJWKS_StaleCacheStillRefreshesAfterNegativeWindow` | the negative window bounds the *rate*, it must not freeze the cache — a rotation is still picked up |
| `TestOIDCFlow_IntrospectionResultIsCached` | FS-5 — 20 authenticated requests ⇒ 1 round trip |
| `TestOIDCFlow_UnreachableIdPIsGatedAndReported` | FS-6 — 11 requests to a down IdP ⇒ 1 round trip; degraded, named, and counted |
| `TestOIDCFlow_InfraFailureIsNotCachedAsADenial` | the recovery half — a valid token works again once the IdP answers |
| `TestOIDCFlow_IntrospectionClientErrorDoesNotArmTheGate` | a 4xx must not arm the gate, and must clear a prior cooldown |
| `TestOIDCFlow_InactiveTokenVerdictIsCached` | the converse — an authoritative verdict *is* cacheable |
| `TestOIDCFlow_ForeignProviderTokenDoesNotStormJWKS` | the end-to-end multi-IdP shape: 25 requests carrying another provider's token ⇒ ≤1 JWKS fetch |

The gate tests drive the cooldown from an injected clock (`gate.now`), matching the
`auth_ldap_gate_test.go` idiom, rather than sleeping.

---

## Residual Risk

- **Bounded revocation delay (new, accepted).** A token revoked at the IdP is now accepted for
  up to `oidcFlowCacheTTL` (2 min), clamped down by the token's own `exp`. This is the
  identical trade the legacy backend has always made and is the price of not re-introspecting
  per request; the alternative — the pre-fix behaviour — is a per-request round trip that
  becomes a per-request 10 s timeout the moment the IdP degrades. Shortening the TTL is a
  one-constant change if an estate needs faster revocation.
- **Unknown-kid latency floor.** A client whose token was signed by a key rotated in during
  the last minute may be denied once and succeed on retry. Denial is fail-closed and
  self-healing within `jwksMinRefreshInterval`.
- **JWKS failures do not feed the `identity_backend` contract row.** They are logged
  (rate-limited) but not counted there. Post-fix a JWKS failure degrades to "serve the last
  good keys", which is correct and self-healing, so it is a log-level event rather than a
  contract-row one. Promoting it to a counted signal is a reasonable follow-up if operators
  ask for it.
- **EC/ES256 keys are still skipped.** `refresh()` parses RSA only. Pre-fix this silently
  wiped the cache; post-fix it is a logged, non-destructive refusal. Actually *supporting*
  ES256 is a feature change, deliberately out of scope for a chaos fix, and is worth its own
  item — an IdP that rotates fully to EC still cannot be validated by this build.
- **`refreshErr` is last-writer-wins across single-flight generations.** A follower
  descheduled for longer than `jwksMinRefreshInterval` could read a newer leader's error.
  Every outcome of that race is fail-closed (a denial or a stale key), and the window requires
  a >1 min deschedule, so it is not defended against.
- **The dispatch loop is still sequential.** With the gate in place a down IdP costs one
  probe per cooldown rather than a timeout per provider per request, which removes the
  goroutine-exhaustion path. Parallelising the loop would further reduce tail latency when
  several IdPs are *slow but up*; that is a performance change, not a resilience one, and is
  left open.

---

## Deliberately Left Open

- **CHAOS-46** — config rollback vs. admin-settings durability (owner decision).
- **CHAOS-43** — OCSP fail-open when the issuer cert cannot be resolved from the chain.
- **CA-13** — cluster-CA rotation still logs-and-returns on every failure branch (the CHAOS-28
  defect class in the *other* CA).
- **CA-4's retry half** — a rotation that fails still waits a full 24 h before retrying.
