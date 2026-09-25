# Security regression review — admin-plane credential entry points

**Date:** 2026-09-14
**Scope:** the admin plane's authentication gating (`ui_middleware.go`,
`ui_auth.go`, `events.go`, `internal/lockout`), reviewed against the recent
change window (PRs #1360–#1374) and the invariants recorded for RISK-012,
RISK-019, CHAOS-57 and CHAOS-63.
**Outcome:** two findings. One HIGH, fixed. One MEDIUM (latent), fixed. Two
pre-existing gaps confirmed still open and reported, not changed.

---

## Executive summary

The recent change window (CDR fingerprint validation, GeoIP diagnostics, MCP
read-first tool classification, OCSP responder authorization, the rate-limit
exempt-check rewrite) introduced **no security regression**. Each was reviewed
against the invariant it touches; findings are in §5.

What the review did surface is older and larger: **the admin plane had four
credential entry points and a brute-force bound on one of them.** The two-tier
account lockout (RISK-012) guarded `POST /api/auth/login`; three other paths
verified the same credentials with none of it. One of those three is on the
public allowlist, which made it an unauthenticated password oracle.

A second, latent finding came out of the same file: the public allowlist
carried a **prefix** for routes that do not exist, which would have made the
first handler written beneath it public by default.

---

## 1. SEC-BASICAUTH-1 — admin credential brute-force bound applied to one of four entry points

| | |
| --- | --- |
| **Severity** | HIGH |
| **CWE** | CWE-307 (improper restriction of excessive authentication attempts), CWE-770 (allocation without limits), CWE-778 (insufficient logging) |
| **OWASP** | A07:2021 Identification and Authentication Failures; A09:2021 Security Logging and Monitoring Failures |
| **Assets** | admin credentials; admin API (full read/write at the account's role); appliance CPU; the audit trail |
| **Status** | FIXED — `ui_basicauth_lockout.go` |
| **Register** | RISK-029 |

### Attack scenario

An attacker who can reach the admin port sends:

```
GET /api/auth/status HTTP/1.1
Authorization: Basic <base64 of admin:guess>
```

The response body says `{"loggedIn": true, …}` on a hit and
`{"loggedIn": false}` on a miss. Repeat at line rate.

`/api/auth/status` is on `isPublicUIAuthPath`, so `uiAuthMiddleware` admits it
with **no credentials at all**, and it is a `GET`, so `securityMiddleware`'s
per-IP API rate limit — which applies only when `isMutating` (POST/PUT/DELETE)
— never sees it. The handler then called `cfg.VerifyUIUser` directly: no
`loginLimiter.Check`, no `RecordFailure`, no audit event.

The same is true of `uiAuthMiddleware`'s Basic Auth fallback (reachable on
every `/api/` route) and of `sseAuthStillValid`.

### Preconditions

Network reach to the admin port. No credentials, no session, no cluster
membership. The default posture ships the UI IP allowlist empty, so the
appliance's own admin port is the only boundary.

### Exploitability / likelihood

High. It is a single unauthenticated HTTP request in a loop; no timing
analysis, no race, no special tooling. Credential-stuffing lists make it
immediately practical against a reused admin password.

### Impact

Three independent consequences:

1. **Brute force / credential stuffing.** RISK-012's lockout — the appliance's
   only barrier against credential guessing — is bypassed by choosing a
   different URL. Tier 2 (the distributed-attack backstop) cannot see failures
   that are never recorded, so IP rotation was free.
2. **CPU exhaustion.** Every attempt is one `bcrypt.DefaultCost` comparison:
   the ~80 ms/attempt constant CHAOS-57 measured, with the same
   `12.5 × GOMAXPROCS` requests/second saturation arithmetic. On an in-line
   gateway that is a traffic-affecting DoS mounted from an unauthenticated
   admin-port request at ~13 KB/s.
3. **No evidence.** A complete brute-force run produced zero audit entries and
   moved no counter. The attack and a quiet appliance were the same scrape.

### Regression analysis

Not introduced by the change window. It is a **divergence that recent hardening
widened rather than closed**:

- CHAOS-57 bounded the *proxy* credential path with `internal/authcost` and
  recorded the admin plane as *"deliberately left: the admin-UI login path
  (bounded by `loginLimiter` instead)"*. That sentence is true of
  `apiAuthLogin` and false of the other three. The premise was checked once, at
  one endpoint, and never re-checked against the others.
- CHAOS-63 bounded the *login endpoint's* username. The Basic Auth paths, which
  take the same untrusted username, were not in scope.

Both are the same pattern the OCSP sweep named in its own note: *a check that
runs at one layer governs a value that reaches another*.

### Fix

One chokepoint, `verifyUIBasicAuth`, applying the **same** `loginLimiter` the
login form uses — same tiers, same window, same trusted-IP bypass, same
`auth.lockout` audit action, same `auth_lockout` alert. No new setting, no new
operator vocabulary.

Four properties are load-bearing:

1. **`Check` runs before verification**, so a locked attempt costs no bcrypt.
   That is what makes it a CPU bound and not merely a guessing bound.
2. **State is shared with the login endpoint**, so endpoints cannot be
   alternated to refresh a budget.
3. **The audit entry is per trip, never per attempt**, with a
   `truncateForAudit` actor — a per-attempt entry would rebuild CHAOS-63's
   durable-log amplifier inside the fix for a different unauthenticated-caller
   defect.
4. **A successful verification clears its pair**, so a legitimate CLI or
   monitoring client making hundreds of calls is never throttled.

The verdict is a three-state answer (`valid` / `invalid` / `lockedOut`)
admitted on `OK()` only: "refused without being verified" is not "verified and
wrong", and collapsing them would answer 401 to a locked-out client and lose
the one signal that the limiter worked.

### Required tests — all present

| Kind | Test |
| --- | --- |
| Negative / regression | `TestSecBasicAuth1_MiddlewareFallbackIsLockoutBounded` |
| Boundary (refusal precedes verification) | `TestSecBasicAuth1_LockedOutCredentialIsRefusedEvenWhenCorrect` |
| Cross-surface state | `TestSecBasicAuth1_LockoutStateIsSharedWithTheLoginEndpoint` |
| Unauthenticated oracle | `TestSecBasicAuth1_PublicAuthStatusIsNotAnUnboundedOracle` |
| Audit / logging | `TestSecBasicAuth1_LockoutTripIsAudited` |
| Positive control | `TestSecBasicAuth1_Control_ValidCredentialsAreNeverThrottled` |
| Positive control | `TestSecBasicAuth1_Control_InterleavedSuccessResetsTheCounter` |
| Lockout-as-DoS control | `TestSecBasicAuth1_Control_AttackerCannotLockOutTheRealAdminsIP` |
| Contract control | `TestSecBasicAuth1_Control_UnauthenticatedStatusStillAnswers` |
| Structural wall | `TestSecBasicAuthWall_EveryCredentialVerifierIsBounded` |
| Structural wall | `TestSecBasicAuthWall_EveryBasicAuthReaderUsesTheChokepoint` |
| Wall control | `TestSecBasicAuthWall_ControlRejectsAnUnboundedVerifier` |

All five defect gates were verified **failing** against the reintroduced
pre-fix shape (direct `cfg.VerifyUIUser`, no limiter) while all four controls
passed — so they target the defect, not the implementation. Both walls were
verified failing against a reintroduced direct call in `events.go`.

### Residual risk

- The bound is per `(IP, username)` and per account. An attacker with many
  source IPs **and** many candidate usernames still gets 5 bcrypts per pair.
  That residual is bounded by the same bcrypt cost that limits the attack
  itself (~`12.5 × GOMAXPROCS` req/s), and is identical to the residual the
  login endpoint has always carried. Closing it fully needs the CHAOS-57
  `internal/authcost` governor extended to the admin plane — a larger change
  with its own fairness questions, recommended as follow-up.
- ~~An oversize username on the Basic Auth path now reaches the lockout maps.
  Key size is bounded by `internal/lockout`'s injective `boundUsername` clamp,
  and entry creation is bcrypt-rate-bounded because `RecordFailure` runs only
  after a verification.~~ **This was WRONG and is corrected below as
  SEC-BASICAUTH-2 (§1a).** `cfg.VerifyUIUser` bcrypts only for a *configured*
  username; an unknown one returns in ~106 ns. Entry creation was therefore not
  rate-bounded at all, and the fix as first written let an unauthenticated
  caller grow the lockout maps without bound. Key *size* is still bounded by the
  clamp; the *count* is now bounded by a per-client failure budget.

---

## 1a. SEC-BASICAUTH-2 — the fix for §1 opened a memory/audit hole on the same endpoint

| | |
| --- | --- |
| **Severity** | HIGH (introduced by this PR, found in review, fixed in this PR) |
| **CWE** | CWE-770 (allocation without limits), CWE-778 |
| **Found by** | Codex automated review of PR #1399 (P1) |
| **Status** | FIXED — `ui_basicauth_lockout.go` |

Wiring `loginLimiter.RecordFailure` into a path with no rate limit means every
failed attempt **creates state**: the tier-1 `(ip, user)` pair *and* the tier-2
account entry, both keyed by an attacker-chosen username, both retained for at
least `lockout.Window` (10 min). `/api/auth/status` is a public GET, so
`securityMiddleware`'s mutating-only limiter never sees it. Measured against the
real handler: **800 limiter entries from 400 unauthenticated requests.**

### The rationale I recorded was false, and that is the transferable part

§1's residual-risk note claimed entry creation was "bcrypt-rate-bounded because
`RecordFailure` runs only after a verification". Measured:

| username | `cfg.VerifyUIUser` cost |
| --- | --- |
| configured (`admin`) | **66.7 ms** (bcrypt) |
| unknown | **106 ns** (map miss, no bcrypt) |

629,518× cheaper. The admin path also has no `dummyBcryptHash` equaliser (the
proxy path's RISK-008 control), so the cheap branch is both cheap *and*
measurable. **A cost that applies only to the branch an attacker never takes
bounds nothing** — a claim about a bound must name the branch the attacker
actually walks.

### The first fix was weaker than no fix on one axis

The first version charged the budget on the failure and then declined to
*record* it. The attempt was still verified and still answered, so the caller
still learned "wrong" — while the account never accumulated failures and
therefore **never locked**. An attacker could burn the budget on ghost
usernames and then guess a real password indefinitely at the window rate:
strictly weaker than the 5-then-15-minutes the lockout gives.

**Shedding the *record* of an answered attempt weakens the bound it exists to
protect; shedding the *attempt* does not.** The budget is therefore consulted
*before* verification, via a new read-only `APIRateLimiter.Over` (`Allow`
charges, so consulting it on every request would bill the requests we mean to
admit), and charged by failures only, keyed on the client and never on the
username — so an over-budget client is refused identically for a right and a
wrong password, and no enumeration oracle appears.

This flaw was caught by a **control test**, not by the defect gate — which is
the argument for writing controls at all.

### Tests

`TestSecBasicAuth2_UniqueUsernameFloodDoesNotGrowLimiterState` (defect gate,
verified failing at 800/120 entries against the pre-fix shape),
`TestSecBasicAuth2_Control_OrdinaryFailuresStillLockOut`,
`TestSecBasicAuth2_Control_OverBudgetRefusalCarriesNoOracle` (the control that
caught the flaw above), `TestSecBasicAuth2_Control_ValidClientIsNeverBudgeted`.

---

## 1b. SEC-BASICAUTH-3 — the §1a budget was a read-then-act pair, so it bounded concurrency, not rate

| | |
| --- | --- |
| **Severity** | MEDIUM (reachable; CWE-770 / A04:2021) |
| **Found by** | Codex review of `53adfff`, PR #1399 (round 2) |
| **Status** | Fixed |

### The defect

`§1a`'s gate was `Over()` (a read-only budget probe) before verification and
`Allow()` (the charge) after it. Each call is mutex-protected; the **sequence**
between them is not. A synchronised cohort of requests from one IP therefore all
observe the same not-yet-incremented count, all pass, and all proceed to
`RecordFailure`. The number admitted per window is the caller's **concurrency**,
not `Burst`.

### The reviewer named the wrong impact, and measuring it found the real one

The review's stated consequence was unbounded limiter-state growth ("two lockout
entries per request despite the advertised 60-entry budget"). That is mostly
**not reachable**, and the reason is worth recording:

| Verification gap | Admitted from a 500-request cohort | Limiter entries |
| --- | --- | --- |
| ~100 ns — unknown username, no bcrypt | **63** | 126 |
| 1 ms | 500 | 1000 |
| ~67 ms — configured username, real bcrypt | **500** | 1000 |

State growth requires **distinct** usernames; distinct usernames are **unknown**
usernames; and an unknown username verifies in ~100 ns (the measurement from
§1a). So the probe→charge window barely exists on exactly the path that grows
state: 63 admitted, i.e. `Burst`+3, essentially the advertised bound.

The reachable damage is the other axis, and it is worse than the one reported.
Against the **real admin username** with wrong passwords, the gap is a full
bcrypt, so all 500 concurrent attempts were admitted and **all 500 ran bcrypt
concurrently from one IP** — measured 3.49 s for the racing shape against 1.11 s
for the bounded one, on a plane with no `internal/authcost` governor. That
defeats load-bearing rule (1) of §1 — *a locked attempt costs no bcrypt* — which
is the CPU-exhaustion half of the original finding. Note the same TOCTOU applies
to `loginLimiter.Check` itself; on `apiAuthLogin` the mutating-POST limiter caps
the arrival rate, and on these public GETs this budget was the only cap.

### The reviewer's prescribed fix would have reopened §1a

The review asked to "make admission and reservation atomic before verification,
then refund the reservation when verification succeeds." The first half is
right. Taken literally, the whole is not: the **refusal** decision necessarily
precedes knowing whether the credential is valid, so charging every request
throttles a legitimate client on work it is not doing — precisely the defect
§1a's rule (2) closed by charging failures only — and a refund cannot un-refuse
a request that already got a 429.

The shape that satisfies both constraints is a reservation **released on
success**: admit-and-charge atomically, hold the charge only for the duration of
the verification, release it if the credential turns out valid, keep it if it
does not.

### Fix

`internal/lockout` gains `Reserve` / `Release` / `Keep`; `Over` is **deleted**
rather than left available, because an unused read-then-act primitive on a
security path is the footgun that produced this finding. Two details are
load-bearing:

- **A refused `Reserve` does not increment.** Charging on refusal would let a
  flood push the window out for the attempts behind it and make the counter
  unreadable.
- **`Release` matches the reservation's `windowStart`.** A charge whose window
  rolled belongs to a window that no longer exists; crediting the current one
  would return an attempt nobody made and silently widen the budget.

`Keep()` disarms a deferred `Release`, so the call site can `defer` it for panic
safety (a verification that panicked produced no failure to count) and still
commit the charge on the failure path.

### Residual risk — recorded, and pinned as a fact

The charge is held across verification, so the admission rule is *failures +
in-flight < `Burst`*. A client issuing more than 60 **simultaneous** Basic-Auth
requests can have some refused with `429` even with correct credentials
(measured: 180 concurrent valid attempts → 60 × `200`, 120 × `429`).

This is unavoidable given the requirement that refusal precede verification, and
it is acceptable because the refusal is retryable, carries `Retry-After`, and is
**never recorded as a failure** — so it cannot feed the account lock. That last
property is asserted, not assumed: the residual test also checks that a
valid-credential burst leaves the client unlocked, which is the lockout-as-DoS
direction the two-tier design exists to prevent.

### The transferable rule

> A gate placed ahead of the work must take its charge in the same critical
> section that admits, or it measures the caller's concurrency instead of the
> caller's rate.

And, separately: **a reported impact is a hypothesis.** Measuring this one moved
the severity from "memory amplifier" (largely self-bounding) to "the CPU bound
was not enforced" (the more serious half of the original finding). The fix would
have been the same; the *understanding*, and therefore what the tests assert,
would not.

### Tests

`internal/lockout/lockout_reserve_test.go` (9): atomicity under a 400-goroutine
cohort, refusal-does-not-charge, balanced reserve/release, idempotent and
zero-safe release, `Keep` surviving a deferred `Release`, the rolled-window
release, rate-not-cap, per-client isolation, and a mixed-traffic run under
`-race`.

`ui_basicauth_lockout_test.go`: `TestSecBasicAuth3_ConcurrentCohortCannotOutrunTheBudget`
(defect gate — **verified failing at 200/200 reached verification** against the
reintroduced `Over`+`Allow` pair),
`TestSecBasicAuth3_Control_SerialValidClientIsNeverRefused` (the control that
rejects the reviewer's literal prescription),
`TestSecBasicAuth3_Control_OrdinaryLockoutStillTrips` (the cheapest way to pass
the defect gate is to refuse everything, which would delete the lockout), and
`TestSecBasicAuth3_ResidualConcurrentValidClientCanBeRefused`.

---

## 2. SEC-PUBLICPATH-1 — a public-allowlist prefix pre-authorised routes that do not exist

| | |
| --- | --- |
| **Severity** | MEDIUM (latent — no exploitable path today) |
| **CWE** | CWE-1188 (insecure default initialization), CWE-306 (missing authentication for critical function) — on the handler that would have been written |
| **OWASP** | A07:2021 |
| **Assets** | admin second factor (TOTP enrolment/removal) |
| **Status** | FIXED — entry removed |
| **Register** | previously tracked as GAP-2 in `docs/design/FRONTEND-CURRENT-STATE.md`, now closed |

`isPublicUIAuthPath` carried `strings.HasPrefix(path, "/api/auth/totp")`. No
`/api/auth/totp*` route is registered anywhere, and `cfg.SetTOTPSecret` /
`cfg.ClearTOTP` have **no production callers at all** — the shipped second
factor is verified inside `apiAuthLogin`'s two-step flow.

The entry was therefore dead today and a landmine tomorrow: a prefix
pre-authorises every future path beneath it, so the first
`/api/auth/totp/enroll` or `/api/auth/totp/disable` handler anyone wrote would
have been born **unauthenticated** — letting a caller bind their own second
factor to an admin account, or strip an existing one. Enrolment is the one TOTP
operation that can never legitimately be anonymous.

This was known and recorded as a "dead entry"; what the review adds is that
*dead* was the wrong risk assessment. The fix removes the prefix (zero
behavioural change today: nothing matched it) and walls the class:
`TestPublicAllowlist_EveryEntryMatchesARegisteredRoute` requires every
allowlist entry to cover at least one registered route, with a mirror test and
a control.

**Note for reviewers:** this changes a locked D0 baseline
(`d0PublicPaths` no longer asserts the two TOTP paths are public). The
rationale is recorded in `d0_auth_safety_test.go` itself. If a pre-session TOTP
step is ever needed, it belongs in the existing `/api/auth/login` two-step
exchange, which is already lockout-fed.

---

## 3. Findings reported, deliberately NOT changed

### 3.1 HTTP Basic Auth does not enforce TOTP (RISK-030, MEDIUM, OPEN)

`apiAuthLogin` requires the second factor via `verifyLoginTOTP`;
`uiAuthMiddleware`'s Basic Auth fallback and `apiAuthStatus` never have. A
valid **password alone** therefore reaches the full admin API at the user's
role — an MFA bypass for every TOTP-enrolled admin (CWE-287).

Not changed inside a lockout fix: requiring TOTP here breaks every CLI and
automation client belonging to a TOTP-enrolled admin. It needs an owner
decision and a migration path — a scoped API token, or a per-user
"allow basic auth" flag. Interim mitigation: restrict the admin port with
`-ui-allow-ip` / `POST /api/ui-allow-ips`.

SEC-BASICAUTH-1 now bounds how fast that password can be guessed. It does not
change what the password unlocks.

### 3.2 `PATCH` sits outside `isMutating` (GAP-4, LOW, latent)

`securityMiddleware`'s CSRF check, 1 MiB body cap and per-IP API rate limit all
key on `POST|PUT|DELETE`. No handler accepts `PATCH` today (verified: the only
occurrence of `MethodPatch` in the tree is a comment in `ui_routes_meta.go`),
so nothing is exploitable — but the first `PATCH` route added would bypass all
three. Recommended fix: add `http.MethodPatch` to `isMutating`. One word, zero
behavioural change today, same landmine class as SEC-PUBLICPATH-1. Left out of
this PR to keep one concern per change.

### 3.3 `isSameOrigin` trusts `X-Forwarded-Host` without a trusted-proxy gate (GAP-5, LOW)

`realClientIP` honours `X-Forwarded-For` only from a configured trusted proxy;
`isSameOrigin` honours `X-Forwarded-Host` from anyone. Practical browser
exploitability is low — `X-Forwarded-Host` is not CORS-safelisted, so a
cross-site fetch carrying it triggers a preflight that this middleware answers
without CORS headers unless the *preflight* is already same-origin — but the
asymmetry with `realClientIP` is real and should be closed by routing
`X-Forwarded-Host` through the same trusted-proxy gate.

---

## 4. What was reviewed and found safe

| Area | Verdict |
| --- | --- |
| `realClientIP` / trusted-proxy XFF walk (RISK-019) | Safe. Joins all XFF field lines (closes the separate-header spoof), walks right-to-left, returns the canonical form, falls back to the peer when every hop is trusted. The malformed-hop `continue` cannot be used to promote a forged left-hand entry, because the rightmost hop is the one the innermost trusted proxy appended. |
| CDR server-fingerprint validation (PR #1374) | Strengthening only. The new `validCDRServerFingerprint` closes a CLI/YAML asymmetry where a typo'd `-cdr-server-fingerprint` silently disabled CDR under the default fail-open mode. `buildCDRTLSConfig` still pins constant-time on both `VerifyPeerCertificate` and `VerifyConnection`, disables session resumption (G123), and refuses to fall back to CA-only unless a CA is actually configured. |
| MCP canary read-first classification (PR #1370) | Safe. `canaryReadFirstClassifier` takes only `(capability, serverID, toolName)` and resolves every authoritative fact from node inventory; promotion requires an armed activation, an exact reviewed record, an unmoved fingerprint and pinned identity, and a four-eyes read-only determination. Promotion is affirmative-only, one-directional, taken in exactly one place, and collapsed into a single predicate so no call site can read `ok` and the class apart. |
| OCSP responder authorization + SSRF sentinel (PR #1369) | Safe. Widening `ssrf.ErrBlocked` to cover the pre-flight refusal was checked against every consumer: the only `errors.Is` call sites are in `internal/ocsp` (counter attribution) and two observability-only predicates in `decryption_observability.go` / `proxy_tunnel.go`. No allow/deny decision changes. |
| Rate-limit exempt view + shared `prefixSet` (PR #1365) | Safe. `prefixFromIPNet`'s family normalisation mirrors `net.networkNumberAndMask` (including the `::ffff:a.b.c.d/104` ⇒ `/8` case that a naive "16 bytes means IPv6" reading gets wrong in the fail-open direction); the single-IP set deliberately keeps raw-string keying so an IPv4-mapped probe cannot widen an exemption; every mutator republishes, pinned per mutator. |
| GeoIP diagnostics row (PR #1371) | Safe. Viewer-gated surface, counts only, no attacker-controlled strings. |
| Admin RBAC walls (D0 / C1 / C1.5 / C2 / C2c / C4) | Green before and after. |

---

## 5. Verification

- `go build ./...` — clean.
- `go vet ./...` — clean.
- `gofmt` — clean.
- `go test ./...` (package main + all `internal/...`) — pass.
- `go test -count=2 -shuffle=on .` (the determinism gate) — pass.
- Every defect gate verified failing against its reintroduced pre-fix shape;
  every control verified passing against the same.
