# Culvert Chaos Engineering Review — 2026-08-01

> **Owner:** Chaos Engineering routine · **Status:** Point-in-time review (repeatable)
> **Method:** Targeted-fix pass against the open-findings register as left by the
> 2026-07-31 run (`CHAOS-ENGINEERING-REVIEW-2026-07-31.md`), which closed
> CHAOS-45 and CHAOS-27/F-12 and named **CHAOS-15/16** the top open item, with
> CHAOS-16 / F-11 as its explicit "suggested next run". The finding was
> re-verified live at HEAD (`33bf8f7`) before any code was written, and the
> verification found a second, unrecorded defect in the same code path that is
> arguably worse than the one on the register.
> **Companion change:** the fix ships with this review (see "Fixed in this change").

---

## Executive Summary

The register's top open item read as a caching nuance: *"LDAP/OIDC negative
results cached (5m/2m): transient IdP outage denies valid creds after
recovery."* Re-verification at HEAD confirmed it and showed it to be a symptom
of something more basic:

> **The auth plane could not tell "no" from "I don't know."**

`LDAPAuth.verify` returned a bare `bool`. A wrong password, a directory
refusing the TCP connect, a service-account bind failure, and a search error
were all the same value: `false`. `OIDCAuth.introspect` did the same — a
transport error, an HTTP 401, an HTTP 503, and a truncated JSON body were
indistinguishable from `active:false`. Three consequences follow from that one
conflation, and all three are in this change.

1. **Outage amplification (the register's item).** The bare `false` was written
   straight into the provider's negative cache for the full TTL. A directory
   that was unreachable for two seconds therefore denied every user who
   authenticated during those two seconds for the **next five minutes** —
   measured from the blip, and continuing long after the directory was healthy.
   The cache exists to protect the IdP from load; under failure it converted a
   momentary infrastructure fault into a multi-minute, self-inflicted user
   outage that no amount of IdP recovery could shorten, and that no operator
   action short of a process restart could clear. The gateway made the outage
   worse than the fault.

2. **An unbounded hang, not previously recorded.** `net.Dialer{Timeout: 10s}`
   bounded only the TCP connect. `conn.Bind` and `conn.Search` had **no
   deadline at all**. A directory that completes the handshake and then goes
   silent — an overloaded DC, a half-open connection surviving a firewall
   state-table flush, a middlebox black-holing the reply — blocked the bind
   **forever**, pinning a proxy request goroutine and its client socket with no
   upper bound. Verified empirically, not by reading: against a listener that
   accepts and never speaks, `Verify` had not returned after 10 seconds and had
   no mechanism that would ever make it return. Under a reconnect storm against
   a sick directory this is unbounded goroutine growth on the request path of
   an in-line appliance.

3. **Invisibility (AU-7 on the standing register).** An IdP outage and a
   credential-stuffing spike produced byte-identical telemetry: a burst of
   `auth FAIL` lines and a rising `statAuthFail`. The operator response to
   those two events is opposite — page the directory team, or block the source
   — and there was no signal anywhere in the product to tell them apart.

**Fixed in this change (CHAOS-16 / F-11 + CHAOS-47):** the providers now
classify each attempt as **answered** (`idpAllowed` / `idpDenied`) or
**unanswered** (`idpUnavailable`). Only answers are cached. Unanswered attempts
are denied, counted per backend, surfaced on `/metrics` and the operator
contract, and paged via a new rate-gated `idp_unreachable` alert. Every LDAP
operation after the connect is now deadline-bounded.

**Posture unchanged, deliberately.** An unanswered attempt still **denies** the
request. Fail-closed is the contract for a security gateway and this change
does not touch it — a "fail open when the IdP is down" mode would be a far
larger, owner-level decision. What changes is that a denial caused by broken
infrastructure is no longer *remembered as if it were a statement about the
user's credentials*, and is no longer silent.

---

## Fixed in this change

### F1 — Infrastructure failure is no longer cached as a credential rejection (CHAOS-16 / F-11) · MED-HIGH

- **Was (re-verified at HEAD):** `auth_ldap.go:104-121` — `ok := a.verify(...)`
  then `a.cacheSet(k, ok)`, unconditionally, where `verify` returned `false`
  from four distinct infrastructure branches (dial, STARTTLS, service bind,
  search). `auth_oidc.go:166-186` — `id, ok, exp := a.introspect(token)` then
  `a.oidcCacheSetIdentityWithExp(...)`, unconditionally, where `introspect`
  returned `false` from four more (request build, transport, non-200, parse).
- **Blast radius confirmed contained:** the outer `authCacheStore` (`store.go`)
  is not involved — `verifyAuthWithSnapshot` returns early when a provider is
  set, so that cache only ever holds local bcrypt results. The registry
  `OIDCFlowProvider` has no cache at all. The defect lived entirely in the two
  legacy providers, which is why the fix is confined to them.
- **Fix:** a tri-state `idpResult` (`auth_health.go`). `LDAPAuth.verify` returns
  `(idpResult, reason)`; `OIDCAuth.introspect` gains a fourth return value
  carrying the unavailability reason. `Verify` / `ResolveIdentity` deny without
  touching the cache when the result is `idpUnavailable`. Because nothing is
  written, **recovery is immediate**: the very next request re-asks the
  provider. No TTL to wait out, no cache to flush, no restart.

**Where the line is drawn, and why it is a security decision rather than a
caching one:**

| Signal | Classification | Reasoning |
|---|---|---|
| OIDC `active:false` in a 200 | **answered** (cacheable) | The only statement about the token RFC 7662 defines |
| OIDC HTTP 401 | unanswered | *Our* client credentials are wrong. Nothing to do with the user's token |
| OIDC HTTP 429 / 5xx | unanswered | Throttling / outage |
| OIDC unparseable 200 body | unanswered | A truncated body or an intercepting middlebox's HTML error page |
| LDAP invalid credentials (49) | **answered** | The everyday wrong-password case — must stay cached |
| LDAP unwilling-to-perform (53), inappropriate-auth (48), insufficient-rights (50), no-such-object (32) | **answered** | Rejections a *healthy* directory issues daily. Classifying these as outages would page the directory team every time an account is locked |
| LDAP busy (51) / unavailable (52) | unanswered | Server-sent, but explicitly a refusal to answer |
| LDAP ErrorNetwork (200) / ServerDown (81) / Timeout (85) / ConnectError (91) | unanswered | Client-side transport codes; the per-request timeout surfaces here |
| Any non-`*ldap.Error` | unanswered | Safe default — see below |
| LDAP service-account bind failure | unanswered, always | Broken directory *or* misconfigured service credential; either way we failed to **ask** the question about this user, so it is not an answer about them |

The default for an unrecognised error is **unanswered**, which is the safe
direction: misclassifying an answer as a no-answer costs one uncached lookup,
while the reverse is a cached denial that outlives the outage — the entire
defect being fixed.

### F2 — Every LDAP operation after the connect is deadline-bounded (CHAOS-47, new) · HIGH

- **Was:** only `net.Dialer{Timeout}`. `StartTLS`, the service `Bind`, the
  `Search` and the user `Bind` were unbounded.
- **Fix (`auth_ldap.go`):** `conn.SetTimeout(ldapOpTimeout)` immediately after
  the dial. go-ldap arms a per-request timer that closes the response channel,
  surfacing as `ErrorNetwork` — which the classifier above already treats as
  *unanswered*, so a timed-out directory is correctly never cached.
- **Proven, not asserted.** `TestLDAP_StalledDirectoryIsReleased` drives a real
  listener that accepts and never writes a byte. With the fix reverted the test
  fails at its 10-second guard with `Verify` still blocked; with the fix it
  returns at the deadline. The test also asserts a **floor** (`elapsed >=
  ldapOpTimeout`) — an earlier draft of it passed while covering nothing,
  because an empty `BindPassword` makes go-ldap reject the simple bind locally
  in ~1 ms without ever touching the socket. That near-miss is recorded in the
  test body so it cannot be reintroduced.
- **Residual (deliberate):** the TLS handshake *inside* `StartTLS` remains
  unbounded — go-ldap calls `conn.Handshake()` on the raw socket with no
  deadline and exposes no accessor to set one. This affects only the
  `ldap://` + `start_tls: true` combination; `ldaps://` routes through
  `tls.DialWithDialer`, which applies the dial timeout to the handshake, so the
  recommended production configuration is fully bounded. A robust fix means
  replacing `DialURL` with a hand-rolled dial + `ldap.NewConn`, which is a
  larger change than this run's scope. Recorded as **CHAOS-48**.

### F3 — An IdP outage is distinguishable from an attack (AU-7) · MED (visibility)

- **`auth_health.go` (new):** per-backend record of unanswered attempts.
- **Surfaces:**
  - `/metrics`: `culvert_idp_unavailable_total{backend}`,
    `culvert_idp_unavailable{backend}` (gauge), and
    `culvert_idp_unavailable_last_age_seconds{backend}`. The whole block is
    **omitted** on a node where no provider has ever failed to answer, rather
    than exported as zeroes — the same reasoning as the durable-write age gauge
    (CHAOS-45): a `0` age would read as "an IdP just failed" on every healthy
    node in the fleet.
  - `/api/diagnostics`: an `idp_reachability` row — `fail` while a provider is
    not answering, `warn` once it answers again, naming the backend and the
    reason.
  - A rate-gated `idp_unreachable` webhook alert, added to the alerts
    supported-event contract and the admin UI event picker.

**Three hazards designed around, each pinned by a test:**

- **Alert flood.** A down IdP fails *every* authenticating request. Un-gated,
  this producer would saturate the bounded webhook queue and evict every other
  alert — the auth-plane fault would take the alerting channel down with it.
  One alert per 5 minutes; the gate re-arms so a persistently-down provider
  keeps paging; the **counter is never gated**, so magnitude survives.
- **Cross-backend gate consumption.** The gates are **per backend**. A shared
  gate would let an LDAP outage silence the page for an unrelated OIDC failure
  inside the same interval — precisely the mistake the 2026-07-31 run had to
  correct for the storage log/alert gates.
- **Disclosure.** `/api/diagnostics` is a **viewer-role** surface with a
  standing no-sensitive-values guardrail, and LDAP/OIDC error text carries
  directory hostnames, bind DNs and introspection URLs. Rather than redacting
  error strings, the record stores only a **closed reason vocabulary**
  (`dial_failed`, `starttls_failed`, `service_bind_failed`, `search_failed`,
  `bind_transport_failed`, `request_build_failed`, `request_failed`,
  `parse_failed`, `http_<status>`). A closed vocabulary cannot leak, so no
  redaction pass exists to be forgotten and no future consumer can reintroduce
  a leak by formatting the record somewhere new. Full error text still goes to
  the log, exactly as before. This is the generalised lesson the previous run
  recorded after nearly disclosing `/data/` paths through the same class of
  surface.

**Recovery is by evidence, never by timer.** Degraded state clears only when a
**definitive answer** is observed from that backend. An IdP that is still down
looks identical to a healthy one when nothing happens to authenticate, so an
elapsed-time heuristic would report recovery with nothing to justify it — the
same reasoning error the storage work had to delete from its own fix. A
*rejection* counts as recovery evidence alongside a success: requiring a
successful login would leave a healthy directory reported as down for as long
as it happened to receive only bad passwords.

### Also in this change

- `OIDCAuth.introspect` now carries an explicit `context.WithTimeout` instead of
  `context.Background()`, matching the registry provider's introspect and making
  the in-flight request cancellable.
- `resetDiagVerdictGlobals` (`diagnostics_test.go`) also resets the IdP health
  global. The aggregate `/api/diagnostics` verdict now folds in
  `idp_reachability`, and `auth_ldap_test.go`'s dial-failure cases record real
  unavailabilities — without this, any test asserting on the aggregate verdict
  would inherit them under `-count=2 -shuffle=on`. Isolation belongs on the
  assertion side, extending the one existing helper rather than adding a second
  rule to remember.
- `LDAPAuth.verify` and `OIDCAuth.introspect` were each split (`connect`,
  `identityFromIntrospection`) to stay inside the repo's funlen/cyclop
  thresholds after the added branches; the OIDC split mirrors the existing
  `identityFromIntrospectionClaims` shape in `auth_oidc_flow.go` and cleanly
  separates the transport half (can be unavailable) from the policy half
  (always an answer).

---

## Failure Scenarios examined (this run)

| Scenario | Behavior before | Behavior after |
|---|---|---|
| Directory unreachable for 2s during a login burst | Every affected user denied for the **full 5 min TTL after recovery**; no signal | Denied while down; **first request after recovery succeeds**; counted, contract row `fail`, one alert |
| Introspection endpoint returns 503 | Token cached as invalid for 2 min past recovery | Not cached; `http_503` recorded; recovery immediate |
| Introspection returns 401 (wrong client secret) | Cached as a user token rejection — user blamed for an operator misconfiguration | Classified unavailable, `http_401` on the contract row pointing at the real cause |
| Intercepting middlebox returns an HTML error page with 200 | Parsed as inactive → cached rejection | `parse_failed`, not cached |
| Directory accepts TCP then goes silent | **Request goroutine blocked forever**; no bound, no recovery | Released at `ldapOpTimeout`; classified unavailable; not cached |
| Connection reset between search and user bind | Cached as "wrong password" | `bind_transport_failed`; not cached |
| Account locked / disabled (LDAP 53) | Cached deny (correct) | Cached deny, **and deliberately not alerted** — a locked account must not page the directory team |
| Wrong password | Cached deny | Unchanged — the cache still absorbs repeat lookups |
| Token genuinely revoked (`active:false`) | Cached deny | Unchanged; verified to still take exactly one IdP round-trip for five lookups |
| IdP outage vs. credential-stuffing spike | Indistinguishable | Distinct counter, gauge, contract row and alert |
| Healthy node | n/a | No IdP series on `/metrics` at all; `idp_reachability` = ok |

## Risk Matrix / Recovery Assessment (updates only)

| Scenario | Before | After |
|---|---|---|
| Transient IdP fault (CHAOS-16) | ❌ amplified into a multi-minute outage with no operator recourse | ✅ **automatic recovery**, immediate — the absence of a cache entry *is* the recovery mechanism |
| Stalled directory (CHAOS-47) | ❌ unbounded goroutine + socket retention; no recovery without restart | ✅ bounded at `ldapOpTimeout`; goroutine released every time |
| IdP outage observability (AU-7) | ❌ indistinguishable from an attack | ⚠️ measured + alarmed; the fault itself is still external and manual to fix |

**Automatic recovery is genuine here, and that is unusual for this register.**
Most chaos remediations in this codebase add detection. This one removes the
mechanism that *prevented* recovery: with the negative no longer cached, a
recovered IdP is serving users again on the next request, with no operator
action, no restart, and no waiting.

## Operational / Security Impact

- **Operational:** zero new configuration — no flag, no config key, no GUI
  setting, so no GUI-parity obligation. Operators gain three Prometheus series,
  an `idp_reachability` contract row that names the backend and the reason, and
  a subscribable `idp_unreachable` event, for a failure class that previously
  had no signal at all.
- **Security:** the exposure removed is a **self-inflicted denial-of-service on
  legitimate users**, triggered by any transient auth-infrastructure fault and
  lasting far longer than the fault. Posture is unchanged in the direction that
  matters — nothing is ever allowed that was not allowed before; unanswered
  attempts still fail closed. The classification table is deliberately
  conservative on the one axis that could weaken security: an unrecognised
  error is treated as *no answer*, which denies and re-asks, never as an
  allow.

## Verification notes (re-checked at HEAD before acting)

- Both cache-write call sites read in context and confirmed unconditional.
- `store.go`'s `verifyAuthWithSnapshot` traced to confirm the outer auth cache
  never sees provider results, bounding the blast radius to the two files.
- `OIDCFlowProvider` (registry path) confirmed to have no cache, so it carries
  no instance of this defect (its missing cache is the separate AU-1 finding).
- go-ldap v3.4.14 `SetTimeout` read end-to-end (`conn.go:356`, timer at
  `conn.go:582`) to confirm it bounds `Bind`/`Search`/`StartTLS`'s extended
  operation and how the timeout surfaces to the caller.
- The unbounded-hang claim was **reproduced** against a real stalling listener
  before the fix, and the regression test was **verified to fail** with the fix
  reverted rather than assumed to bite.
- `go build ./...`, `go vet ./...`, `gofmt -l` clean; full `go test ./...`
  green; `-race` and `-count=2 -shuffle=on` green on the touched packages;
  `make api-verify` green (no API schema change — the operator contract is a
  list of checks, and the new row needs no spec edit).
- `golangci-lint` could not be run to completion in this environment: it panics
  inside its own package loader, and the panic **reproduces unchanged on a
  clean `origin/main` tree**, so it is a local toolchain/version mismatch and
  not a property of this change. Function sizes and cyclomatic complexity were
  therefore checked manually against the repo's configured thresholds
  (funlen 80 lines / cyclop 15) and both new/split functions sit well inside
  them.

## Open-findings register — status after this run

| ID | Sev | Title | Status |
|---|---|---|---|
| CHAOS-16 (F-11) | MED | LDAP/OIDC error-path negatives cached → transient IdP outage denies valid credentials past recovery | **FIXED** (this change) |
| CHAOS-47 | HIGH | LDAP `Bind`/`Search` have no post-dial deadline → a stalled directory pins request goroutines without bound | **FIXED** (this change) — found during re-verification, not previously on the register |
| CHAOS-48 | LOW | The TLS handshake inside go-ldap's `StartTLS` is unbounded (affects `ldap://` + `start_tls` only; `ldaps://` is bounded by the dialer) | **OPEN (new)** — needs `DialURL` replaced by a hand-rolled dial + `ldap.NewConn` |
| CHAOS-15 | MED | Session HMAC rotation has no dual-key grace window (fleet-wide logout + cross-node reject window) | OPEN — **now the top open item** |
| CHAOS-46 | MED | Config rollback restores `default_action` / `rewrite_rules` / `ip_filter_mode` to the RUNNING config only; admin-settings durability reverts them at startup | OPEN (owner decision) |
| CHAOS-19 | LOW-MED | Audit-write failures dropped with no counter | OPEN — cheap, the observer pattern is now established twice over |
| CHAOS-18 | MED | DP snapshot applied before local store inits | OPEN |
| CHAOS-08 | MED | No semantic floor on snapshots | OPEN (policy decision required) |
| CHAOS-13/14 | MED-LOW | No jitter on legacy feed tickers; no gRPC keepalives on CP/DP channel | OPEN |
| CHAOS-11 / CHAOS-10 | MED | Upstream all-down / ClamAV error posture | MITIGATED — remainder is posture config in both cases |
| CHAOS-20/21, 24/25/26, 28 | LOW-MED | Feed staleness metrics; CA-rotation window race; release-platform lows; unretried renewal | OPEN |
| CHAOS-27 (relay) | LOW-MED | Double write-block escapes the idle reaper | OPEN — still carrying an ID shared with the closed config finding; **renumber** |

### Suggested next runs

1. **CHAOS-15** — dual-key grace window for session HMAC rotation. Now the
   highest open item, and the last piece of the "auth-plane outage
   amplification" pair this run half-closed: rotation is currently an instant
   fleet-wide logout with a cross-node rejection window during the 30s DP poll.
2. **CHAOS-19** — the audit writer drops on I/O failure with no counter. It
   does not route through `AtomicWrite`, so it needs its own counter, but the
   observer→counter→contract-row→alert shape is now established twice
   (CHAOS-45, this run) and can be copied directly.
3. **CHAOS-48** — bound the `StartTLS` TLS handshake, closing the last
   unbounded operation in the LDAP path.
4. **CHAOS-27 ID collision** — renumber the surviving relay finding.

## Residual Risk

- **`StartTLS` handshake (CHAOS-48).** One unbounded operation remains, on the
  `ldap://` + `start_tls` path only. Documented above with the reason it was
  not fixed here.
- **Not caching denials costs directory load in one narrow case.** Rejections
  the classifier cannot recognise as server-issued are re-asked each request
  instead of being cached. Deliberate, and bounded in practice: the everyday
  rejection codes (49, 48, 50, 53, 32) are all classified as answers and stay
  cached. The un-rate-limited bcrypt/proxy-auth path remains a separate open
  concern (AU-3).
- **Detection, not prevention, for the outage itself.** The provider being down
  is an external fault. This change guarantees the operator learns, and that no
  user stays blocked a second longer than the fault lasts; it cannot make the
  IdP answer.
- **Fail-closed remains the only posture.** There is no admin-selectable
  "allow while the IdP is down" mode. For a security gateway that is the right
  default, but it means an IdP outage is still a user-visible outage. Making
  the posture selectable (mirroring the YARA/scan model) is an owner-level
  decision, deliberately not taken inside a chaos fix.
- **The alert rate gate is a constant** (5 min), not operator-tunable —
  consistent with the other chaos-hardening thresholds in the codebase
  (recorded deferral, same class as `storageWriteAlertInterval`).
- **`/healthz` and `/readyz` are untouched.** Whether an auth-degraded node
  should fail readiness is the same open policy question as CHAOS-09/F-08;
  flipping readiness during an IdP outage would restart every container in the
  fleet at once, which is a self-inflicted outage on top of an external one.
