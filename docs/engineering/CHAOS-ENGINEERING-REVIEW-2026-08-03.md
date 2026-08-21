# Culvert Chaos-Engineering Review — 2026-08-03

**Window:** identity / authentication under infrastructure failure
**Method:** evidence-first source review; every claim below cites the code path.
Findings were driven by the previous run's "suggested next runs" list
(`CHAOS-ENGINEERING-REVIEW-2026-07-31.md` §"Suggested next runs", item 1).
**Change shipped with this review:** one contained fix — **CHAOS-47**.

---

## 1. Executive Summary

The identity path fails **closed** under infrastructure failure, which is the
correct posture and was never in doubt. What this run found is that it did not
**recover**.

> A failure to REACH the directory or the IdP was written into the auth cache as
> if it were a verdict about the user's credential. Denying during the outage is
> right; remembering the denial for 2–5 minutes afterwards is not. The
> degradation therefore **outlived the fault** — a one-second directory restart
> bought minutes of 407s for every user who happened to authenticate during it,
> on a gateway that authenticates per request.

That is the "broken recovery" class this program exists to find, and it had two
aggravating properties:

1. **Self-inflicted amplification.** The cache is keyed by *credential*, not by
   backend. So the outage window did not produce one stale entry, it produced
   one per active user, each expiring on its own schedule. Recovery was not an
   event; it was a several-minute smear.
2. **Structurally invisible.** The only signal was `culvert_requests_auth_fail`,
   which counts wrong passwords and unreachable directories in the same
   counter. An IdP outage and a credential-stuffing attack looked identical on
   the dashboard — and the operator response to those two is opposite. This is
   the long-standing **AU-7** observability gap from the 2026-07-04 register.

The fix is shipped and green (§7). The rest of the identity domain reviewed in
this window is genuinely well-built and is documented as such in §2, with the
code paths that provide the resilience.

---

## 2. Failure Scenarios — this window

Severity key: **C**ritical / **H**igh / **M**edium / **L**ow / **✓** handled
well (positive finding, with the code that provides the resilience).

| # | Scenario | Verdict | Sev | Evidence |
|---|----------|---------|-----|----------|
| CHAOS-47 | **Directory / IdP unreachable → the denial is cached.** Every infrastructure branch (dial refused, STARTTLS error, service-account bind failure, search error, introspection transport error, IdP 5xx, malformed body) returned the same bare `false` a wrong password returns, and `Verify` cached it for `CacheTTL`. A blip outlived itself by up to 5 min (LDAP) / 2 min (OIDC), per credential. | GAP → **FIXED** | **H** | pre-fix `auth_ldap.go` `verify` (all branches `return false`) + `Verify` `cacheSet(k, ok)`; `auth_oidc.go` `introspect` (`return nil,false,nil`) + `oidcCacheSetIdentityWithExp`; consumed on the request path at `proxy.go:222` via `cfg.resolveAuthIdentity` |
| CHAOS-48 | Not caching the negative, on its own, would trade a stale-deny bug for a **stampede**: a hard-down backend would put every request through a full dial/HTTP timeout (10 s each), converting an IdP outage into goroutine + FD exhaustion on the gateway. Recorded because it is the reason the naive fix is wrong. | Addressed in the same change | M | `auth_ldap.go` dial timeout 10 s; `auth_oidc.go` `http.Client{Timeout: 10s}` |
| CHAOS-49 | The **IdP registry** path (`auth_oidc_flow.go`, the newer multi-IdP surface) has no result cache at all, so it cannot be poisoned — but for the same reason it re-introspects on **every request**, sequentially, per enabled provider, each with a 10 s ceiling. An IdP brownout adds `N × latency` to every authenticated request. | GAP | M | loop `proxy.go:207-219`; `auth_oidc_flow.go` introspection has no cache field (contrast `auth_oidc.go`) — this is AU-1/AU-13 from the 07-04 register, still open |
| AU-7 | An IdP outage was indistinguishable from a brute-force spike: both surfaced only as `culvert_requests_auth_fail`. | GAP → **CLOSED** by this change | M | new `culvert_auth_backend_unavailable{,_total}` + `culvert_auth_backend_gated_denials_total` (`metrics.go`), `identity_backend` contract row (`diagnostics.go`), `idp_unreachable` alert |
| — | **Wrong password / inactive token is still cached.** The authoritative-deny cache is what keeps a credential-stuffing flood off the directory, and the fix deliberately preserves it — only *unreachable* is excluded. | ✓ | — | `auth_ldap.go` `Verify` (cacheSet only when `err == nil`); pinned by `TestOIDC_AuthoritativeDenyIsStillCached` |
| — | Admin-UI login is **not** affected: `VerifyUIUser` is local-roster bcrypt only and never consults the external provider, so an IdP outage cannot feed the lockout counter and lock a real admin out. Checked explicitly because that would have escalated the finding. | ✓ | — | `store.go:901-923`; lockout at `ui_auth.go:54` operates on that path only |
| — | Empty password never reaches the backend and is not charged to backend health, so a scanner spraying blanks cannot light up the IdP-down alarm. | ✓ | — | `auth_ldap.go` `Verify` first branch; pinned by `TestLDAP_EmptyPasswordNeverTouchesTheBackend` |
| — | All admin-configured IdP egress dials through `ssrfSafeDialContext`, with HTTPS + non-private pre-validation and `io.LimitReader`-capped bodies. Unchanged by this work. | ✓ | — | `auth_oidc.go` `NewOIDCAuth` transport wiring; `decodeStrictJSON` |
| — | Auth caches remain bounded (5 000) with eviction and HMAC-keyed lookup keys (heap-dump safe). | ✓ | — | `store.go:240-292`, `auth_oidc.go` `oidcCacheSetIdentityWithExp` |

---

## 3. Risk Matrix

| Risk | Finding | Likelihood | Impact | Priority | Status |
|------|---------|------------|--------|----------|--------|
| R1 | CHAOS-47 — cached infrastructure failure keeps denying valid credentials after recovery | **High** (a directory restart, an IdP deploy, a DNS blip, a failover are all routine) | High (fleet-wide inability to browse; looks like a Culvert bug, not an IdP bug) | **P0** | **FIXED** |
| R2 | CHAOS-48 — un-gated retry against a down backend | Medium (only if R1 were fixed naively) | High (goroutine/FD exhaustion during the outage) | P0 | Addressed in the same change |
| R3 | CHAOS-49 — registry path re-introspects per request, per provider, no cache/breaker | High (every request) | Medium (latency + IdP amplification) | P2 | OPEN |
| R4 | AU-7 — outage indistinguishable from attack | High | Medium (wrong operator response) | P1 | **CLOSED** |

---

## 4. Recovery Assessment

**Before:** recovery was neither automatic nor bounded by the fault. It was
bounded by `CacheTTL` *per credential*, counted from each user's last failed
attempt — so the tail extended past the outage by up to a full TTL, and there
was no operator action that shortened it short of restarting the proxy (which
drops every in-flight tunnel) or editing and re-saving the auth config (which
calls `SetProvider` → `cache.clear()`). Neither is discoverable from the
symptom.

**After:** recovery is automatic, evidence-driven, and bounded by seconds:

- an unreachable outcome arms a per-backend gate for `authBackendProbeCooldown`
  (3 s) — requests are denied without a round trip, so a hard-down backend costs
  one probe per cooldown instead of one 10 s timeout per request;
- the first probe after the cooldown that **reaches** the backend clears the
  gate for every caller at once (`recordReachable`), because reachability is a
  property of the backend, not of the credential;
- nothing about the outage is written to the cache, so there is no stale state
  to age out afterwards.

**Recovery evidence, not elapsed time.** The degraded gauge and the contract row
clear only when a reach is *observed* — the same rule `storage_health.go`
established for durable writes (CHAOS-45), and for the same reason: a backend
that nobody happens to query looks identical to a healthy one under a timer.

---

## 5. Operational Impact

New signals, all fed from one memory-only record (`auth_backend_health.go`):

| Surface | Signal |
|---|---|
| `/metrics` | `culvert_auth_backend_unavailable_total` (counter — detected outages, one per probe), `culvert_auth_backend_unavailable` (gauge — 1 while a backend is unreachable), `culvert_auth_backend_gated_denials_total` (counter — the blast radius: requests denied without contacting the backend) |
| `/api/diagnostics` | `identity_backend` row: `fail` while unreachable with an operator action, `warn` once a reach is observed (the incident stays visible for the rest of the process), `ok` when never seen |
| Webhook alert | `idp_unreachable`, rate-limited to one per 5 min, `HasSubscriber`-gated (this producer is on the request path and its rate is set by an external fault) |
| Log | one line per 5 min naming the backend, the count, and the cause |

**Alert semantics worth stating for the runbook:** `idp_unreachable` firing means
*users cannot authenticate*, and it is **self-clearing** — there is no
Culvert-side action to take once the identity service answers again. The
operator action is entirely on the directory/IdP side (reachability: DNS, route,
firewall, TLS; or the service account's credentials).

**Cause text is admin-scoped.** The error text names the configured endpoint (an
LDAP URL, an introspection host), so it goes to the log and the alert only. The
`/api/diagnostics` row is a **viewer**-role surface with a standing
no-sensitive-values guardrail, so it carries the backend name and the counts and
never the cause — the same boundary the CHAOS-45 run drew for filesystem paths.

---

## 6. Security Impact

The change **narrows** nothing and widens nothing about who gets in:

- Every request that was denied before is still denied. The fail-closed posture
  during an outage is unchanged — only the *memory* of the denial is dropped.
- The authoritative-deny cache (wrong password, inactive token, missing group)
  is preserved exactly, so the anti-credential-stuffing property of that cache
  is intact.
- The user-bind branch now distinguishes LDAP result code 49
  (`invalidCredentials`) from a connection that dropped mid-bind. Only 49 is
  treated as a password rejection; anything else is infrastructure. This is
  strictly more precise than the previous "any bind error means wrong password",
  and it cannot admit anyone — both paths still deny.
- The gate can only ever produce **more** denials than a probe would (it denies
  without asking), never fewer.

The one genuinely new security-relevant behaviour is a *positive* one: a
service-account bind failure — a wrong or expired Culvert service credential, a
config error that used to silently look like every user having a bad password —
is now visible as an infrastructure fault with its own alert.

---

## 7. Suggested PR (this PR)

Shipped here:

- **`auth_backend_health.go` (new)** — the per-backend half-open gate
  (`authProbeGate`), the process-wide health record, the `HasSubscriber`-gated
  `idp_unreachable` producer, and the test reset helper. Modelled on
  `storage_health.go` so there is one pattern for "a dependency failed at
  runtime", not two.
- **`auth_ldap.go`** — `verify` now returns `(bool, error)` where the error means
  *infrastructure*; `Verify` caches only when the directory answered, gates when
  it did not, and distinguishes LDAP result code 49 from a dropped connection.
- **`auth_oidc.go`** — `introspect` gains an error return with the same
  contract; RFC 7662 makes the split clean, since an inactive token is reported
  as HTTP 200 with `active:false`, so any non-200 is an endpoint fault and never
  a verdict about the caller's token.
- **`metrics.go`** — three series (§5).
- **`diagnostics.go`** — the `identity_backend` operator-contract row.
- **`internal/alerts/store.go` + `static/index.html`** — the `idp_unreachable`
  event, documented in the contract and subscribable from the Alerts panel (GUI
  parity).
- **`diagnostics_test.go`** — the identity-backend global folded into
  `resetDiagVerdictGlobals`, extending the existing helper rather than adding a
  second isolation rule to remember (the convention the 07-31 run recorded).

Deliberately **not** bundled: CHAOS-49 (a cache + breaker for the IdP registry
path). It is a different file, a different cache-design decision — how to key a
positive cache when identity is provider-resolved — and it deserves its own
review surface.

---

## 8. Required Tests — all green

`auth_backend_health_test.go`:

| Test | Pins |
|---|---|
| `TestOIDC_IdPOutageIsNotCached_RecoversImmediately` | The headline regression, end to end: IdP down → denied and **nothing cached**; still down → 25 further requests denied with **zero** additional round trips (the stampede guard) and the blast radius counted; IdP recovers → the **very next probe succeeds**, with no TTL waited out. Drives the gate from an injected clock, so recovery is asserted deterministically rather than by sleeping. |
| `TestOIDC_AuthoritativeDenyIsStillCached` | The other direction — a reachable IdP answering "inactive" is introspected **once** across five attempts, and is not reported as an outage. |
| `TestOIDC_MalformedResponseIsTreatedAsUnavailable` | HTTP 200 with a non-RFC-7662 body (captive portal, misrouted ingress) fails closed, is not cached, and is recorded as backend-unavailable. |
| `TestLDAP_UnreachableDirectoryIsNotCached` | Same regression on the directory path; also asserts the gate suppresses re-dials and that the operator record names the backend. |
| `TestLDAP_EmptyPasswordNeverTouchesTheBackend` | A blank-password spray is rejected locally and is **not** charged to backend health. |
| `TestAuthProbeGate_OneProbePerCooldown` | Exactly one probe per cooldown, and the gate re-arms on **grant** rather than on the result — so a probe that never reports back cannot leave the gate open against a still-dead backend. |
| `TestAuthProbeGate_ReachClearsImmediately` | One observed reach releases every caller at once. |
| `TestAuthBackendHealth_RecordAndRecover` | Evidence-based recovery of the gauge; cumulative counters survive recovery. |
| `TestOIDC_UnreachableIdPFiresAlert` | Exactly one alert, and rate-limiting holds for a continuing outage. |
| `TestDiagnostics_IdentityBackendRow` | `ok` → `fail` (with an operator action) → `warn` after recovery. |

Verification run: full `go test ./...` green; `go test -race -count=2
-shuffle=on` green over the auth/diagnostics surface (the determinism class the
CI gate catches); `go vet ./...` and `gofmt` clean; `TestBenchGate_*` green.

*Environment note for future runs:* the `golangci-lint` binary in this container
is built against Go 1.25 and panics on this Go 1.26 module
(`package requires newer Go version go1.26`). That is a container limitation,
not a repo state — CI supplies its own. Lint was reviewed against the repo's
documented rules by hand instead (CWE-117 barriers, `errcheck`, cyclomatic
budget, copylocks — the last covered by `go vet`).

---

## 9. Residual Risk

- **CHAOS-49 (open).** The IdP-registry path still re-introspects per request
  per provider. Not a correctness risk, but an IdP brownout is amplified into
  request latency with no breaker. Next run's top candidate.
- **The 3 s cooldown is a constant.** It is a deliberate, recorded deferral: it
  is short enough that recovery latency is not operationally interesting, and
  making it configurable would add a config surface (with GUI parity) for a knob
  with no known tuning need. If a deployment ever needs it, the finding to cite
  is this one.
- **Blast radius during the outage is real and unchanged.** Requests denied
  while a backend is down are still denied — that is the fail-closed contract.
  What changed is that they stop the moment the backend answers, and that the
  count is now measurable (`culvert_auth_backend_gated_denials_total`) instead
  of being invisible inside a generic auth-failure counter.
- **The gate is per-process.** In a cluster, each node discovers the outage
  independently and each pays one probe per cooldown. That is correct — node A
  being unable to reach the directory is not evidence about node B's
  reachability — but it does mean the probe rate against a recovering directory
  scales with fleet size (one per node per 3 s, which is negligible next to the
  per-request rate it replaces).

---

## 10. Open-findings register — status after this run

Statuses relative to the 2026-07-31 table. Findings not listed are unchanged;
the 2026-07-05 review remains the authority for detailed write-ups.

| ID | Sev | Title | Status |
|---|---|---|---|
| CHAOS-47 | HIGH | Identity-backend infrastructure failure is cached as an authoritative deny — the outage outlives the fault by a full cache TTL, per credential | **FIXED** (this change) — gate + no-cache-on-unreachable + counter/gauge/alert/contract row |
| CHAOS-48 | MED | Un-gated retry against a down identity backend would turn an IdP outage into a dial-timeout stampede | **ADDRESSED** (this change) — half-open gate, one probe per cooldown |
| CHAOS-49 | MED | IdP-registry path re-introspects per request per provider; no cache, no breaker (the surviving half of AU-1/AU-13) | **OPEN (new)** — next run's top candidate |
| CHAOS-16 / F-11 | MED | Auth error-path negative caching pins users out past an outage | **CLOSED** by CHAOS-47 for the cached backends (LDAP + legacy OIDC); the registry remainder is CHAOS-49 |
| CHAOS-15 | MED | HMAC rotation has no grace window | OPEN — now the top open item in its domain |
| CHAOS-46 | MED | Config rollback restores some surfaces to the RUNNING config only; admin-settings durability not extended | OPEN (owner decision) |
| CHAOS-27 (relay) | LOW-MED | Double write-block escapes the idle reaper (ID collision with the config finding) | OPEN — still wants renumbering |
| CHAOS-18 | MED | DP snapshot applied before local store inits | OPEN |
| CHAOS-08 | MED | No semantic floor on snapshots | OPEN (policy decision required) |
| CHAOS-19 | LOW-MED | Audit-write drop has no counter | OPEN — the observer pattern from CHAOS-45/47 now applies cleanly |
| CHAOS-13/14 | MED-LOW | No jitter on legacy feed tickers; no gRPC keepalives on CP/DP channel | OPEN |
| CHAOS-28 | LOW-MED | Failed rotation-triggered renewal not retried until the 30-day window | OPEN |
| CHAOS-20/21 | LOW-MED | Feed staleness metrics; CA-rotation window race | OPEN |
| CHAOS-24/25/26 | LOW | Release-platform delta lows | OPEN |

### Suggested next runs

1. **CHAOS-49** — positive+negative cache and a breaker for the IdP registry
   path, reusing the gate this run introduced.
2. **CHAOS-19** — counter on the audit writer's dropped writes; it is an append
   path (`internal/audit`), so it needs its own counter rather than the
   `AtomicWrite` observer, wired to the same `/healthz` + contract surface.
3. **CHAOS-13/14** — jitter the legacy feed tickers; gRPC keepalives on the
   CP/DP channel.
4. **CHAOS-27 ID collision** — renumber the surviving relay finding so the
   register stops carrying one ID for two unrelated defects.

---

## 11. A note on how this finding was found

Worth recording, because the search that produced it is repeatable. The defect
is not visible in any single function: `verify` returning `false` on a dial
error is locally reasonable, and `Verify` caching its result is locally
reasonable. It only becomes a defect at the **join** — where a value that means
"I could not ask" is stored in a structure whose contract is "this is the
answer".

The generalisable question is therefore: *for every cache, retry, and
memoisation in the system, does the stored value distinguish "the dependency
said no" from "the dependency did not answer"?* Applied to this codebase it
already found CHAOS-47 here; the same question against the scan-result cache
produced CHAOS-10/17 in an earlier run, and against the category DB it is what
makes `catdb`'s read-error → "not found" behaviour worth a second look. It is
the cheapest single lens this program has produced so far, and future runs
should start with it.
