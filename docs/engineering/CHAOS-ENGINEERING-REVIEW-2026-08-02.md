# Culvert Chaos Engineering Review — 2026-08-02

> **Owner:** Chaos Engineering routine · **Status:** Point-in-time review (repeatable)
> **Method:** Targeted-fix pass against the open-findings register as left by the
> 2026-07-31 run (`CHAOS-ENGINEERING-REVIEW-2026-07-31.md`), which closed
> CHAOS-45 / CHAOS-27 and named **CHAOS-16 / F-11** as suggested next run #1 and
> **CHAOS-15/16** as the top open item. The finding was re-verified live at HEAD
> (`b9fafff`) before any code was written; verification confirmed it and widened
> it — the defect reaches one step further into the LDAP bind than the register
> recorded, and the OIDC half covers a misconfiguration case that is worse than
> the outage it was filed for.
> **Companion change:** the fix ships with this review (see "Fixed in this change").

---

## Executive Summary

The register's item read: *"LDAP/OIDC negative results cached (5m/2m): transient
IdP outage denies valid creds after recovery."* Re-reading the code at HEAD
showed the mechanism precisely, and showed it to be one instance of a single
modelling error repeated in two engines:

> **Both external auth backends had a two-valued result type for a
> three-valued question.** `Verify` could say *allow* or *deny*. It had no way
> to say *I could not ask*. So every infrastructure failure — a refused dial, a
> failed STARTTLS, a service-account bind rejection, a search error, an HTTP
> transport error, a 500, a 401, an unparseable body — was funnelled into the
> same `false` that a wrong password produces, and then **cached as if it were a
> statement about the credential.**

Two consequences followed, and both are worse than the register's one-line
summary:

1. **The outage outlived itself by orders of magnitude.** A 200 ms blip on the
   directory produced a *five-minute* denial for every credential that happened
   to miss the cache during it (two minutes for OIDC). The blip was over; the
   denial was not. From the user's side this is the classic "I got locked out
   for no reason and then it fixed itself" incident that generates a ticket
   nobody can ever reproduce.

2. **The outage was invisible, because it was disguised as its own opposite.**
   Both engines logged `LDAP auth FAIL` / `OIDC auth FAIL` — the exact words a
   wrong password produces. There was no counter, no gauge, no alert and no
   diagnostics row anywhere in the product for "the directory is unreachable".
   An operator watching authentication failures spike during an IdP outage sees
   what looks like a **credential-stuffing attack**, and the correct response to
   the thing they think they are seeing (tighten, lock out, investigate the
   users) is the opposite of the correct response to what is actually happening.

The OIDC path carried an additional case that is not an outage at all. RFC 7662
gives the IdP exactly one way to say something about a token: a 200 carrying
`active`. A **401** from the introspection endpoint means *our* client
credentials are wrong. Before this change that misconfiguration was rendered as
"every user's token is inactive" — and cached. A wrong `client_secret` after a
credential rotation therefore presented as a fleet-wide, self-sustaining mass
rejection of valid tokens.

**Fixed in this change (CHAOS-16 / F-11):** results are three-valued. An
*answer* is cached exactly as before. A *failure* is indeterminate: still
denied — an unreachable directory must never admit anyone — but not recorded as
a credential decision, and now visible as an outage on four operator surfaces.
LDAP additionally gained the post-dial deadline it never had.

**Posture unchanged, deliberately.** Nothing here makes an auth failure
fail-open. The security property (an auth backend that cannot answer denies) is
byte-for-byte what it was. What changes is that the denial stops when the
outage stops, and that the operator can tell the two apart.

---

## Fixed in this change

### F1 — An auth-backend outage is no longer cached as a credential decision (CHAOS-16) · MED

- **Was (re-verified at HEAD):**
  - `auth_ldap.go` — `verify()` returned bare `false` from five distinct
    branches: dial error, STARTTLS error, service-account bind error, search
    error, and *any* failure of the user bind. `Verify()` then called
    `cacheSet(k, false)` unconditionally, pinning it for `CacheTTL` (5m default).
  - `auth_oidc.go` — `introspect()` returned `active=false` for a request-build
    error, a `client.Do` error, a non-200 status and a parse error, and
    `oidcCacheSetIdentityWithExp` cached it for `CacheTTL` (2m default).
- **Fix (`auth_health.go`, new):** `authBackendOutcome` — `backendAllow` /
  `backendDeny` / `backendIndeterminate`, with `allowed()` (indeterminate
  denies) and `determinate()` (only an answer is cacheable as a decision). The
  type is deliberately named for the *distinction that matters*, which is
  ANSWERED vs UNANSWERED rather than allow vs deny.
- **Fix (`auth_ldap.go`):** every branch classified. The two-step bind is now
  split — `connectAndBindService` owns dial, deadline, STARTTLS and the service
  bind, and *cannot* produce anything but indeterminate, because every failure
  it can hit is our connectivity or our service credential and never a verdict
  on the end user's password. `verify` owns the search and the user bind.
  - **The user bind is the subtle one.** `conn.Bind(userDN, password)` failing
    was previously "wrong password" full stop. It is now only a decision when
    the directory says so — `isLDAPCredentialRejection` (result code 49
    *Invalid Credentials*, which is also where AD folds disabled/expired/locked
    accounts, and 48 *Inappropriate Authentication*). A network error, a
    timeout, *busy*, *unavailable*, *unwilling to perform* and any unrecognised
    error are indeterminate. **Unrecognised falls to indeterminate on purpose**:
    the cost of being wrong that way is one extra bind per credential per 5s;
    the cost of being wrong the other way is the finding, reintroduced at the
    last possible step.
  - `len(res.Entries) != 1` stays a **decision** — the directory answered, it
    just has no single match, and that is stable until the directory changes.
- **Fix (`auth_oidc.go`):** only a 200 that parses reaches the decision
  branches. Transport error, non-200 (401/403/429/5xx alike) and parse failure
  are indeterminate. Everything after a successful parse — `active:false`,
  invalid declared expiry, missing required scope, missing required audience, no
  canonical subject — remains a full-TTL decision.
- **Cache policy:** determinate → the configured `CacheTTL` (unchanged, still
  clamped to the token's own `exp`). Indeterminate → `authIndeterminateTTL`.

**On `authIndeterminateTTL` (5s), the one deliberate residual.** Not caching an
indeterminate result at all would be more correct in isolation — the outage
would then never outlive itself by even a millisecond. It would also point a
load amplifier at a backend that is already in trouble: every cache-missing
request during the outage opens its own connection and holds a goroutine for the
full dial timeout, so a struggling directory gets hit *harder* precisely while it
is failing, and a recovering one can be knocked straight back down by the queued
retry storm. The engineering call is therefore to remember an unanswered attempt
for **seconds instead of minutes**: long enough to collapse a request storm into
roughly one attempt per credential per interval, short enough that recovery is
felt almost immediately. A user can still be denied for up to 5s after the IdP
returns. That is the residual, and it is three orders of magnitude smaller than
the 5m/2m that caused the finding.

### F2 — LDAP operations after the dial are deadline-bounded (F-11, second half) · MED

- **Was:** `DialWithDialer(&net.Dialer{Timeout: 10s})` covers the **TCP connect
  only**. `Bind` and `Search` had no deadline at all, so a directory that
  accepts the connection and then stalls — a wedged AD replica, a firewall
  black-holing established flows, a server in a long GC pause — hung the request
  goroutine indefinitely holding a connection. This is strictly worse than a
  refused dial, which at least fails fast.
- **Fix:** `conn.SetTimeout(ldapOpTimeout)` immediately after the dial, which
  applies to every subsequent request on the connection. The hang becomes a
  bounded, *classifiable* network error — and because of F1 that error is now
  indeterminate rather than a cached denial.

### F3 — An auth-plane outage is distinguishable from a credential failure · HIGH (visibility)

This is the half the register did not ask for and the code needed most. Before
this change the product had **no signal of any kind** for "an auth backend is
down", which is why the failure mode reads as an attack.

- **Record (`auth_health.go`):** per-backend `unreachable` counter, last failure
  time, sanitized reason, and `lastOK` — the most recent *observed answer*.
- **Recovery is by evidence, never by a timer.** Degraded clears only when the
  backend is observed to answer. A directory that is still down looks exactly
  like a healthy one if nothing happens to ask it, so ageing the state out would
  report recovery with nothing to justify it. This is the CHAOS-45 Codex P1
  lesson carried across to the auth plane, and it is pinned here by
  `TestAuthBackendDegraded_SilenceIsNotRecovery` (a 24h-old failure with no
  observed answer still reports degraded).
- **Surfaces:**
  - `/metrics`: `culvert_auth_backend_unreachable_total{backend}` and
    `culvert_auth_backend_degraded{backend}`. Rows for a backend that has never
    failed are **absent, not zero** — nothing here probes, so "no failures
    recorded" can equally mean "nobody has authenticated", and a green row would
    assert knowledge the process does not have. HELP/TYPE is emitted once per
    metric name with rows appended, because a repeated HELP line is a scrape
    parse error.
  - `/api/diagnostics`: an `auth_backend_reachability` row — `fail` while
    degraded, `warn` once an answer has been observed (a healed outage still
    denied requests during the window, which is exactly what an operator
    investigating "users could not log in at 14:20" needs). Contributes nothing
    when no backend has ever failed, matching the metrics rule.
  - `auth_backend_unreachable` webhook alert, added to the alerts supported-event
    contract and the admin UI event picker.
  - A log line that deliberately does **not** use the words an authentication
    failure produces: *"Auth: backend "ldap" UNREACHABLE — requests are being
    denied fail-closed"*.
- **Two hazards designed around, both pinned by tests:**
  - **Alert flood.** A down directory fails *every* request. Un-gated this
    producer would saturate the bounded webhook queue and evict every other
    alert — the auth outage would take the alerting channel down with it. Log
    and alert are gated to one per `authBackendAlertInterval` (5m); the
    **counter is never gated**, so magnitude survives; the gate re-arms so a
    backend that stays down keeps paging.
  - **Cross-backend muting.** The gates are **per backend**, not global. A
    permanently-broken secondary backend must not consume the gate and silence
    the page for the primary one going down — the shared-gate hazard the
    CHAOS-45 run had to split apart after review.
  - The alert also goes out through a `go`-spawning seam that **does nothing at
    all when nobody is subscribed**: this producer fires from request goroutines
    at request rate, and spawning a delivery goroutine per failure for an alert
    with no recipient would inject goroutine churn into the default posture.
- **The reason text is redacted at the recording boundary
  (`redactAuthReason`).** This is the CHAOS-45 disclosure lesson applied before
  it could bite rather than after. `/api/diagnostics` is a **viewer-role**
  surface, and the errors these reasons come from carry topology: an
  `*url.Error` embeds the configured introspection URL, and the `*net.OpError`
  underneath embeds the **resolved address**. Shipping the raw text would have
  published the corporate IdP's hostname and its internal IP to every read-only
  admin the first time the directory hiccupped. The configured endpoint and any
  IPv4/IPv6 address are stripped; the operator-actionable part — the failure
  class, *"connection refused"*, *"i/o timeout"*, *"certificate has expired"* —
  survives, and the raw error is still written verbatim to the operator **log**
  by the calling provider. Redaction is done at the single boundary the record
  passes through, so a future consumer cannot reintroduce the leak by
  formatting the record somewhere new. Pinned by
  `TestAuthBackendReason_RedactsEndpointTopology`, which also asserts the
  failure class is not redacted away (a reason that says nothing is as useless
  as no reason at all). It is worth naming the pattern: the surrounding
  diagnostics checks already follow it — the SAML base-URL rows describe the
  defect without ever echoing the configured value.
- **Hot-path cost on a healthy node: one relaxed atomic load.** Every
  determinate outcome calls `noteAuthBackendAnswered`, which is on the proxy
  authentication path; until something has actually failed it short-circuits on
  `authEverUnreachable` and never touches the lock.

### Tests

`auth_backend_outage_test.go` (new):

- `TestOIDC_IntrospectionOutageDoesNotOutliveItself` — the end-to-end recovery
  proof. The IdP 503s, recovers, and the **same token** is accepted. The window
  is elapsed by rewinding the cached entry's expiry by exactly
  `authIndeterminateTTL` rather than sleeping, which is what makes it
  discriminating: under the pre-fix code the entry carried the provider's
  `CacheTTL` (1h in the fixture), so advancing five seconds would not have
  expired it and the recovered IdP would still have been denied.
- `TestLDAP_UnreachableDirectoryIsNotCachedAsACredentialDecision` — a real
  refused dial (a loopback port bound then closed); asserts fail-closed, the
  entry marked indeterminate, and a lifetime bounded by `authIndeterminateTTL`
  rather than the 5m `CacheTTL`.
- `TestOIDC_Non200IsNotACredentialDecision` — 401 / 500 / 502.
- `TestLDAP_CredentialRejectionClassification` — table over result codes 49, 48,
  `ErrorNetwork`, busy, unavailable, unwilling-to-perform and a plain error.
- `TestLDAP_DecisionKeepsTheConfiguredTTL` /
  `TestOIDC_ActiveFalseStaysAFullTTLDecision` — **the other direction.** A fix
  that made every negative uncacheable would turn each rejected credential into
  a directory round-trip per request; a real answer must stay cacheable.
- `TestAuthBackendAlert_RateGatedPerBackend` — 25 failures → 25 counted, 1
  alert; a second backend still pages; the gate re-arms.
- `TestAuthBackendDegraded_SilenceIsNotRecovery`,
  `TestAuthBackendHealth_HealthyPathTakesNoLock`,
  `TestAuthBackendHealth_RecordIsBounded`,
  `TestAuthBackendHealth_ReasonIsSanitized`.
- `TestMetrics_AuthBackendSeries` (including absent-not-zero and the single
  HELP line), `TestDiagnostics_AuthBackendRow` (fail → warn).

`diagnostics_test.go`'s `resetDiagVerdictGlobals` now also clears the
auth-backend record: the aggregate verdict folds in the new rows, and the record
is process-global, so any earlier test that drove a real LDAP/OIDC failure would
otherwise leak a `fail` row into the verdict assertions — the `-count=2
-shuffle=on` determinism class the CI gate catches. Isolation stays on the
assertion side, extending the one existing helper rather than adding a second
rule to remember.

**Both directions of the core fix were mutation-checked** before the review was
written: reverting the TTL split (indeterminate back to `a.ttl`) fails the LDAP
and OIDC regressions with the pre-fix lifetimes visible in the failure output
(`4m59.99s` / `59m59.99s`). A test that cannot fail is not evidence.

---

## Failure Scenarios examined (this run)

| Scenario | Behavior before | Behavior after |
|---|---|---|
| LDAP unreachable for 200 ms during a login | Cached deny for **5 minutes** past recovery; log says "LDAP auth FAIL" | Denied for the attempt; entry expires in ≤5s; counted, alerted, contract row names the backend |
| LDAP accepts the TCP connection then stalls | Request goroutine hangs **indefinitely** (dial timeout does not cover Bind/Search) | Bounded by `ldapOpTimeout`, classified indeterminate, not cached as a denial |
| LDAP service-account credential wrong / expired | Every user cached-denied for 5m as if their own password were wrong | Indeterminate; users denied while it lasts but not pinned; the row tells the operator to check the service account |
| Directory rejects the password (code 49) | Cached deny 5m | **Unchanged** — a real decision, still cached 5m |
| Username does not exist | Cached deny 5m | **Unchanged** — the directory answered |
| OIDC introspection endpoint returns 503 | Cached "inactive" for 2m past recovery | ≤5s, counted + alerted |
| OIDC `client_secret` rotated, endpoint returns 401 | Fleet-wide cached mass rejection of valid tokens, indistinguishable from expiry | Indeterminate + `auth_backend_unreachable` naming the backend; recovers the moment the secret is fixed |
| IdP returns `{"active":false}` | Cached deny 2m | **Unchanged** — cached 2m |
| Auth backend down, 10k requests | 10k lines of "auth FAIL", no metric, no alert; reads as credential stuffing | 1 alert per 5m per backend, every failure counted, gauge at 1, contract row `fail` |
| Backend recovers | Invisible; users stayed denied for the TTL tail | Gauge → 0 and row → `warn` **on an observed answer**, never on a timer |
| Two backends, one permanently broken | n/a | Independent gates — the broken one cannot mute the page for the other |
| Healthy node, no external backend configured | n/a | Zero cost (one atomic load), no metric rows, no diagnostics row |

## Risk Matrix / Recovery Assessment (updates only)

| Scenario | Before | After |
|---|---|---|
| IdP blip (CHAOS-16 / F-11) | ❌ denial amplified to 5m/2m past recovery; invisible; presents as an attack | ✅ denial bounded to the outage + ≤5s; alarmed, measured, named on the operator contract |
| LDAP post-dial stall | ❌ unbounded goroutine hang | ✅ bounded by `ldapOpTimeout` |
| Introspection endpoint misconfigured (401) | ❌ self-sustaining mass rejection | ⚠️ still denies while misconfigured (correct), but is now reported as a backend fault, not as user error |

**Automatic recovery: yes, and that is the point of the change.** Recovery
requires no operator action and no cache flush — it happens within
`authIndeterminateTTL` of the backend answering again. Nothing is retried in the
background (no hidden retries, no infinite retries); the next real request
re-consults the backend.

## Operational / Security Impact

- **Operational:** zero new configuration; no flag, no YAML key, no behavioural
  toggle. Operators gain two Prometheus series, a diagnostics row, a webhook
  event, and a log line that says *unreachable* rather than *auth FAIL* — for a
  failure class that previously had no signal at all. The practical value is
  triage time: "the directory is down" and "someone is spraying credentials"
  produced identical evidence before this change and demand opposite responses.
- **Security:** the fail-closed posture is unchanged and was never in question.
  The security-relevant improvement is the *misconfiguration* case — a rotated
  `client_secret` or an expired service-account password used to present as a
  fleet-wide user-credential failure, which is precisely the kind of signal
  confusion that gets an incident mis-triaged. The residual exposure is
  availability, not confidentiality: users are still denied while a backend is
  down, by design.

## Verification notes (re-checked at HEAD before acting)

- Every `return false` in `LDAPAuth.verify` and every `return nil, false, nil` in
  `OIDCAuth.introspect` read in context and classified individually; the
  register's summary named the two cache TTLs but not the user-bind branch,
  which is where the misclassification is easiest to miss.
- `conn.SetTimeout` confirmed present in `go-ldap/ldap/v3 v3.4.14` and
  documented as applying to subsequent requests on the connection.
- **The newer registry path was checked and is NOT affected by this finding.**
  `OIDCFlowProvider.introspect` (`auth_oidc_flow.go`) has no result cache at all,
  so it cannot cache an outage — it has the *opposite* problem, an IdP round-trip
  per request per provider (AU-1/CHAOS-13-adjacent), which is a separate open
  item and deliberately not touched here.
- The alert-deadlock hazard that shaped CHAOS-45 does not apply: `fireAlert` →
  `Dispatch` → the retry queue touches storage, not auth, so there is no
  re-entry. The `go`-spawn seam is kept anyway because the caller is a request
  goroutine and `Dispatch` can block on a disk write.
- `go build ./...`, `go vet ./...`, `gofmt -l` clean; full `go test ./...` green;
  `go test -race -count=2 -shuffle=on` green over the auth, diagnostics, metrics
  and storage-health tests.
- `golangci-lint` could not be run locally: the installed binary is built with
  go1.25 and the module requires go1.26, so it panics during type-checking. The
  changed functions were kept inside the configured thresholds by hand — the
  LDAP two-step bind was split into `connectAndBindService` + `verify`
  specifically to stay clear of the cyclop-15 and funlen-80 limits the combined
  function would have approached.

## Open-findings register — status after this run

Statuses relative to the 2026-07-31 table. Findings not listed are unchanged;
the 2026-07-05 review remains the authority for detailed write-ups.

| ID | Sev | Title | Status |
|---|---|---|---|
| CHAOS-16 (F-11) | MED | LDAP/OIDC error-path negatives cached 5m/2m → an IdP blip denies valid credentials past recovery; no LDAP post-dial deadline | **FIXED** (this change) — three-valued outcome, 5s indeterminate bound, `SetTimeout`, counter/gauge/row/alert. T12 is now GREEN |
| CHAOS-15 | MED | Session HMAC rotation has no dual-key grace window (fleet-wide logout, cross-node reject window) | OPEN — **now the top open item**, and no longer shares a row with CHAOS-16 |
| CHAOS-16 (breaker) | LOW | No per-backend circuit breaker: during an outage each distinct credential still costs one backend attempt per `authIndeterminateTTL` | **OPEN (new, split out)** — bounded, not eliminated. A real breaker (open after N consecutive indeterminate, single probe to close) changes deny latency for legitimate users during *partial* outages, so it is an owner decision rather than something to fold silently into an observability fix |
| CHAOS-46 | MED | Config rollback restores `default_action` / `rewrite_rules` / `ip_filter_mode` / rate-limit settings to the RUNNING config only — admin settings are never written, so those parts silently revert at startup | OPEN (07-31) |
| CHAOS-27 (relay) | LOW-MED | Double write-block escapes the idle reaper (the 07-10 finding) | OPEN — **ID collision still unresolved**; should be renumbered |
| CHAOS-11 | MED | Upstream-pool all-down fails open to direct | MITIGATED (07-26B) — remainder: `upstream.fail_mode` posture config |
| CHAOS-10 | MED | ClamAV error mid-request fails open silently | MITIGATED (07-26) — remainder: `scan.on_error` posture config |
| CHAOS-18 | MED | DP snapshot applied before local store inits | OPEN |
| CHAOS-08 | MED | No semantic floor on snapshots | OPEN (policy decision required) |
| CHAOS-28 | LOW-MED | Failed rotation-triggered renewal not retried until the 30-day window | OPEN |
| CHAOS-13/14 | MED-LOW | No jitter on legacy feed tickers; no gRPC keepalives on CP/DP channel | OPEN |
| CHAOS-19/20/21 | LOW-MED | Audit-write counter; feed staleness metrics; CA-rotation window race | OPEN — CHAOS-19 remains cheap and now has **two** precedents to copy (storage, auth) |
| CHAOS-24/25/26 | LOW | Release-platform delta lows | OPEN |

### Suggested next runs

1. **CHAOS-19** — the audit writer drops on I/O failure with no counter
   (`internal/audit`). It is an append path and does not go through
   `AtomicWrite`, so it needs its own counter wired to the `/healthz` +
   contract surface. Two runs have now established the exact shape to copy
   (observer → counter → degraded-by-evidence → gated alert → contract row →
   absent-not-zero metric); this is the cheapest remaining silent-failure class.
2. **CHAOS-15** — session-HMAC rotation grace window. Now the top open item, and
   it is the last piece of the auth-plane amplification story: a deliberate
   rotation is currently an instant fleet-wide logout with no dual-key overlap.
3. **CHAOS-13/14** — jitter the legacy feed tickers; gRPC keepalives on the
   CP/DP channel.
4. **CHAOS-27 ID collision** — renumber the surviving relay finding so the
   register stops carrying one ID for two unrelated defects. Flagged by the last
   two runs; it costs one edit and it is now actively confusing.

## Residual Risk

- **The 5s indeterminate window is a real, deliberate residual.** A user can be
  denied for up to `authIndeterminateTTL` after the backend recovers. Removing
  it entirely trades that for a load amplifier aimed at a recovering directory —
  see the reasoning above. It is a constant, not operator-tunable, consistent
  with the other chaos-hardening thresholds in the codebase (recorded deferral,
  same class as `storageWriteAlertInterval` and the release-catalog thresholds).
- **No circuit breaker.** During an outage, N distinct credentials still cost N
  backend attempts per window. Bounded, not eliminated (split out as its own
  register row above).
- **Classification is by error code, and directories vary.** Result codes 49/48
  are the answer set; everything else is treated as infrastructure. A directory
  that signals a credential rejection through some other code will produce an
  indeterminate result — fail-closed and self-correcting on the next attempt,
  the safe direction, at the cost of not caching that rejection.
- **Recovery evidence is per backend, not per credential.** Any observed answer
  from a backend clears its degraded state, which is correct for "is the
  directory reachable" and deliberately weaker than "did THAT user's auth
  succeed".
- **The registry IdP path is untouched** and still has no introspection cache at
  all (AU-1). It cannot exhibit this finding, but it carries the inverse cost —
  one IdP round-trip per provider per request — which remains open.
- **`/healthz` and `/readyz` are untouched.** Whether a node whose only auth
  backend is unreachable should fail readiness is CHAOS-09 / F-08's open policy
  decision. Flipping it would eject the entire fleet from the load balancer
  during an IdP outage — turning a partial authentication failure into a total
  outage, which is exactly the self-inflicted escalation this run exists to
  prevent.
