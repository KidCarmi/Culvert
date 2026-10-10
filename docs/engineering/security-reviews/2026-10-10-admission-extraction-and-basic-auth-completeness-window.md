# Security review — admission-engine extraction, guidance decomposition, and the completeness of the SEC-BASIC-1 fix

**Date:** 2026-10-10
**Reviewer role:** Security Regression Engineer (scheduled run)
**Baseline:** `83328fd` (2026-09-26) — the commit that recorded the previous
review (`docs/engineering/security-reviews/2026-09-24-ci-evidence-and-reporter-window.md`)
**Head:** `fbf6a37` (`main`, 2026-10-10)
**Scope reviewed:** the whole window — 54 commits, 15 merge commits, 8
substantive pull requests: #1420 (admin-plane Basic 2FA/lockout bypass +
delegated-handler RBAC parity), #1501 (HA resume-budget test seam), #1508
(threatfeed bench gate under `-race`), #1522 (shutdown registry extraction),
#1523 (admission state ownership), #1524 (admission engine extraction), #1525
(frontend audit repair), #1592 (agent-guidance decomposition, Go 1.26.9,
`x/net` v0.60.0).

**Method.** Prioritised by live blast radius, and — following this series'
standing weighting — deliberately weighted toward **completeness of the
previous window's fix**. The largest single change in the window is a pure
refactor of the IP-filter and rate-limiter core (1,198 lines moved out of
root `security.go`), so the second priority was behavioural equivalence of
moved security logic rather than a reading of the new code alone.

1. **The surface #1420 just fixed.** SEC-BASIC-1 closed an unauthenticated
   2FA-and-lockout bypass by routing every admin-plane HTTP Basic credential
   through one chokepoint. The first question asked here was whether every
   sibling row on that surface — every other request path that verifies an
   admin password — carries the same controls, or only the rows the fix
   happened to enumerate.
2. **The admission extraction (#1523/#1524).** `IPFilter.Allowed` and
   `RateLimiter.Allow`/`AllowClusterAware` are the gateway's admission
   decision. Reviewed for decision-logic drift, fail-open/fail-closed
   inversion, cluster wire compatibility, and instance confusion introduced
   by moving package globals to per-instance fields.
3. **The guidance decomposition (#1592).** The eagerly-loaded instruction
   surface shrank from 464,534 bytes to 14,850. Reviewed for whether any
   CI/CodeQL-enforced security rule fell out of the always-loaded set, and
   whether the new gate can actually fail.
4. **Shutdown and HA (#1522/#1501).** Both touch controls whose failure mode
   is silent: a collapsed shutdown budget drops audit/log flush hooks, and a
   shortened fencing-lease budget grants writable leadership early.

---

## 1. Executive summary

**One finding, the audit half fixed in this change:**

- **SEC-PWCHANGE-1 (LOW, insufficient logging)** — `apiAuthChangePassword`
  re-verifies the account's current password through `cfg.VerifyUIUser` and,
  before this change, wrote **no audit record when that verification failed**.
  It audits success. A refused attempt was therefore the only credential
  verification left on the admin plane that left no trace at all — the
  missing-compliance-record half of the defect SEC-BASIC-1 had just closed for
  HTTP Basic, surviving on a sibling row of the same surface. **Fixed here**,
  with tests.

  Scope note, because it changes what this finding is: this path's *other*
  difference from the login handler — that it consults no lockout — is **not**
  a finding. #1420 examined this exact caller, admitted it to
  `TestSECBASIC1_VerifyUIUserHasNoOtherRequestPathCaller`'s allowed set, and
  recorded the trade in that allowance: the username is session-derived (no
  enumeration surface, no unauthenticated reach), the method is mutating (so
  `apiLimiter` bounds the bcrypt rate), and adding a lock would let a session
  holder lock *themselves* out of the login flow. This review reached the same
  conclusion independently and leaves the behaviour alone; §6.2 offers a
  bounding shape the owner may prefer, as a hardening option, not a defect.
  What that allowance does not address — and what is fixed here — is the audit
  trail.

**No security regression was found in any other change in the window.** In
particular:

- The admission extraction is a **mechanical** move. Every admission decision
  function (`Allowed`, `contains`, `Allow`, `AllowClusterAware`, `FreshCount`,
  `expire`, `add`, `grow`, `IsExempt`) is byte-identical to its pre-extraction
  body apart from the receiver and renamed identifiers. The documented
  fail-closed posture for a corrupt filter mode — deny all rather than coerce
  to "block" — survives verbatim. The cluster gossip JSON contract
  (`ip`/`count`/`node_id`/`remote_counts`, including `nil`→`null`) is
  preserved in main's wire DTOs with a conversion shim, so a mixed-version
  cluster still shares counts.
- The toolchain and dependency work in #1592 is **security-positive**: twelve
  standard-library advisories and GO-2026-6617 (an HPACK encoder race in
  `x/net` v0.59.0 reachable from the inspected-H2 tunnel and the control-plane
  gRPC server) are closed, with the pin moved consistently in `go.mod`, both
  production builder stages and the maintenance E2E builder, each by digest,
  `GOTOOLCHAIN=local` retained and no workflow override.
- The guidance decomposition does not drop an enforced rule. Every
  CI/CodeQL-enforced convention (`logger.Printf`, `sanitizeLog` + `%q`, inline
  `isPrivateHost`, contextual I/O, handler-level `requireRole`,
  audit-then-`saveConfigVersion` with its recorded exclusions) is in the
  eager surface. The `lint budget` change in that PR is a **timeout**
  increase (5m→10m analysis, 12m→15m job), not a rule relaxation: no
  `.golangci.yml` change and no new `nolint`/`nosec` suppression anywhere in
  the window.

**Process observation, not a code finding.** This series has a gap: the
previous entry is dated 2026-09-24, and the window reviewed here is the first
since. The `docs/security-reviews/` and `docs/engineering/security-reviews/`
directories are two generations of the same series with no index, which makes
the current baseline non-obvious to the next run. See §10.1.

---

## 2. Security findings

### SEC-PWCHANGE-1 — a refused current-password verification leaves no audit record

**Affected contract.** Admin-plane credential verification, specifically its
*observability* tier. SEC-BASIC-1 (`ui_basic_auth.go`) names the missing audit
record as one of the four controls whose absence made the Basic path a defect:
"No `auth.login.fail` entry was ever written, so a sustained password-guessing
campaign against the admin plane left no trace in the compliance record."
`apiAuthChangePassword` verifies a password and had exactly that property.

The lockout and rate-limit controls on this path were weighed and accepted by
#1420 (see the scope note in §1), so this finding is **only** the audit
record — the one element of the SEC-BASIC-1 control set that the recorded
allowance does not mention.

**File/line evidence.** `ui_auth.go` — `apiAuthChangePassword`, the current-
password branch. Before this change:

```go
// Verify current password.
if _, ok := cfg.VerifyUIUser(username, body.CurrentPass); !ok {
    http.Error(w, "current password is incorrect", http.StatusForbidden)
    return
}
```

`cfg.VerifyUIUser` (`store.go`) is a bare bcrypt compare: no lockout, no rate
limiter, no second factor, no record. The success path immediately below it
writes `auditEvent(r, "auth.password_change", username, …)`, so the handler
audits the outcome an operator already knows about and not the one that
indicates an attack.

**Attack scenario.** An attacker holds a valid admin-UI session for an account
but not its password — a stolen or XSS-exfiltrated `ps_ui_session` cookie, a
borrowed workstation, or a Viewer session obtained legitimately. The session
grants the account's role, but not persistence: it expires, and it cannot be
used to change the password without presenting the current one. The attacker
therefore guesses the current password against
`POST /api/auth/change-password`, which answers 403 for a wrong guess and 200
for a right one. On success they set a password of their own: the session
access becomes durable account takeover, the legitimate operator is locked
out of their own account, and the recovered plaintext is available for reuse
wherever that credential is shared.

**Preconditions.** A valid session for the target account (`username` comes
from `sessionAdmin(r)`, not from the request body, so an attacker can only
guess the password of the account they already hold a session for) and
`RoleViewer` or above. Same-origin (the CSRF check applies to mutating
methods).

**Exploitability.** Moderate once the precondition is met. `apiLimiter`
allows 60 mutating API requests per IP per minute, so a guesser gets ~86,400
attempts per day from one source IP with no total cap — the accepted trade
described in §1. What makes it a *finding* is that, before this change, none
of those attempts appeared anywhere: the rate was bounded, the visibility was
zero. The two together are what the login path has and this path did not.

**Likelihood.** Low. It needs a prior session compromise, which is itself the
larger event; the value this adds is persistence and credential recovery.

**Impact.** Account takeover (persistence beyond session lifetime), operator
lockout, plaintext credential recovery, and — the part this review weights
most — **no compliance record of any of it**. A sustained guessing campaign
against this endpoint produced zero audit entries, so the audit trail could
not distinguish "the operator rotated their password" from "an attacker
recovered it and rotated it". Each attempt also costs a full bcrypt (~80 ms of
exclusive CPU, CHAOS-57) on the process that serves the data plane; the
`authcost` governor is wired only to the proxy's `verifyAuthFrom`
(`store.go`), not to `VerifyUIUser`, so admin-plane bcrypt is bounded only by
`apiLimiter` on this path.

**Affected assets.** Admin credentials and roster (`ui_users.json`), the audit
ring and its persisted compliance record, and gateway CPU.

**CWE.** CWE-778 (Insufficient Logging) — the half fixed here; CWE-307
(Improper Restriction of Excessive Authentication Attempts) — the half left
as an owner decision. Also CWE-307-adjacent CWE-770 (Allocation Without
Limits) for the bcrypt cost.

**OWASP.** A09:2021 Security Logging and Monitoring Failures (primary);
A07:2021 Identification and Authentication Failures.

**Severity.** LOW. It is not an authentication bypass: the session precondition
means the attacker already holds the account's authority. It would be MEDIUM
in a deployment with long-lived sessions or widely-held Viewer sessions, where
the step from session to durable credential is the whole attack.

**Regression risk of the finding itself.** Pre-existing, not introduced in
this window. It is a surviving instance of the class #1420 closed, and the
mechanism by which it survived is worth recording, because it is subtler than
an overlooked call site: the caller was **not** overlooked. It sits in the
wall test's allowed set with a written justification. That justification
reasons about enumeration surface, unauthenticated reach and bcrypt rate — the
three properties that made the Basic path dangerous — and is correct on all
three. It simply does not mention the fourth control in the same list, the
audit record, so the allowance reads as a complete clearance while covering
three quarters of the set. An explicit exemption with partial reasoning is
harder to spot than a missing one, since the wall test goes green either way.

---

## 3. Risk rating

| Item | Rating | Basis |
|---|---|---|
| SEC-PWCHANGE-1 (audit gap) | **LOW** — fixed here | Needs a session; impact is loss of the compliance record |
| Change-password attempt bounding | **Not a finding** — recorded deliberate trade | Accepted by #1420 in the wall test's allowance; optional hardening in §6.2 |
| Admission extraction (#1523/#1524) | **No regression** | Decision bodies byte-identical; wire contract preserved |
| Guidance decomposition (#1592) | **No regression** | Enforced rules all eager; new gate self-tests |
| Toolchain / `x/net` bump (#1592) | **Security-positive** | 13 advisories closed; pins consistent, digest-pinned |
| Shutdown extraction (#1522) | **No regression** | Zero-value `Options` falls back to the production constants |
| HA resume seam (#1501) | **No regression** | Test-only fields, production default 0; source-scan guard test |
| Threatfeed bench gate (#1508) | **No regression** | Test-only, `-race`-conditional |

---

## 4. Regression analysis

### 4.1 Admission engine extraction (#1523, #1524) — the largest change

1,198 lines left root `security.go` for `internal/admission/engine.go`. A
normalised diff of the pre-extraction file against the new package isolates
**73 changed executable lines**, every one of which is one of: the package
clause, an import or root-alias removal, a lowercase→exported rename
(`prefixFromIPNet`→`PrefixFromIPNet`, `hotThresholdPct`→`HotThresholdPercent`,
`newRateLimiter`→`NewRateLimiter`), or a package global becoming an instance
field (`clusterRateLimitEnabled`→`r.clusterEnabled`,
`clusterCounts`→`r.remoteCounts`, `ipFilterPublishHook`→`f.publishHook`).
No conditional, comparison, ordering or lock discipline changed.

Four things were checked specifically because a mechanical move is where they
hide:

- **Fail-closed on a corrupt mode survives.** `Allowed` still answers `""` →
  allow (disabled), `"allow"` → allowlist, `"block"` → blocklist, and *any
  other value* → **deny all**, with the reasoning intact that coercing to
  "block" would turn a corrupted allowlist deployment into a blocklist that
  admits every unlisted IP. A freshly constructed filter resolves to
  `emptyIPFilterView` (mode `""`, disabled) rather than nil-dereferencing.
- **Instance confusion does not occur.** `clusterEnabled` moving from one
  process-wide `atomic.Bool` to a per-limiter field would silently degrade
  cluster-aware limiting to local-only if any caller touched a different
  instance than the one serving traffic — an attacker distributing requests
  across nodes would get `limit × nodes`. Every production caller
  (`controlplane_client.go` gossip loop, `metrics.go`, `ui_cluster.go`,
  `freshness.go`) operates on the singleton `rl` from `admission.go`; the only
  other constructor call in production is the snapshot path's new `IPFilter`.
  `controlplane_admission_ownership_test.go` pins this at the production
  composition.
- **Wire compatibility is preserved.** `HotCount` dropped the JSON tags that
  `RateLimitDelta` carried, and `RateLimitGossip`/`RateLimitBroadcast` left
  the engine entirely — which would have been a silent cluster-wide
  degradation to per-node rate limiting against an older peer. Main retains
  all three DTOs with their exact historical field names in
  `cluster_ratelimit_wire.go`, and `rateLimitWireDeltas` converts while
  preserving `nil`→`null`. `admission_contract_test.go` pins the conversion.
- **The publish hook was test-only before and after.** Moving it per-instance
  is strictly safer (no cross-test global); production never installs one.

The snapshot restore path (`applySnapshotAdmission`) changed only by extracting
a helper and replacing a bare `&IPFilter{single: …}` literal with
`newIPFilter()`. It still sets the mode, bulk-loads with `AddAll`, and only
then publishes the new filter into `ipf` — so the transient state of a
half-loaded allowlist is never the one serving requests, and the pre-existing
non-atomic `ipf = newIPF` assignment pattern is unchanged by this work.

### 4.2 Guidance decomposition (#1592)

The eager instruction surface shrank by 97% (464,534 → 14,850 bytes), with the
removed content routed into `docs/agent-context/`. For a repository whose
security contracts live substantially in prose, instruction loss is itself a
regression vector, so this was checked two ways:

- **Corpus preservation.** `docs/agent-context/check.py --self-test` passes:
  108 pinned blocks at byte and blob identity, 117 declared route edges, 450
  navigation links, 10 static routing cases, and **21 negative controls
  rejected** (a gate that cannot fail is not a gate). A keyword sweep of 40
  security terms across the old `CLAUDE.md` and the new corpus found no term
  whose occurrence count fell.
- **Retrievability of what CI enforces.** Every rule the pipeline actually
  enforces is in the eager set (`conventions.md`, imported by root
  `CLAUDE.md`). Invariants that now appear only under `history/` — mTLS, PKCE,
  bcrypt, `0600`/`0700` file modes, host-header handling — were each verified
  to be enforced in code with tests rather than carried by prose alone, which
  is the disposition `AGENTS.md` prescribes ("verify it in the current
  owner/tests"). Root `security.go` survives as the 50-line SSRF/host seam, so
  `isPrivateHost` remains at the location `conventions.md` and CodeQL expect.

The new `docs-guidance` CI job is a net gain: it runs whenever a
guidance-shaped path changes (including paths the checker exists to *refuse*,
such as an unregistered nested `AGENTS.md`), fails explicitly rather than
silently skipping when the comparison base cannot be resolved, and is a
hard `require-success` member of the aggregate on a guidance diff.
`fast_gate_race_shards_test.go` pins all of that, including new negative
controls. Coverage floors were extended to the extracted
`internal/admission/engine.go` and `freshness.go` at 70% each, which matters
because the old `security.go 70` floor now applies to a 50-line file of
one-line delegators and no longer protects the logic it used to cover.

### 4.3 Shutdown registry extraction (#1522)

Same mechanical shape as the admission move. The one new failure mode a
constructor-with-`Options` introduces is a zero-valued `Options` collapsing
the watchdog budget to nothing, which would abandon shutdown hooks instantly —
including audit and log flush hooks, i.e. loss of compliance records on every
restart. `Registry.timing()` falls back to `DefaultGrace`/`DefaultMinSlice` on
a zero field, and `New` panics on a negative one. Production constructs with
only `Logf` set, so it runs on the previous constants.

### 4.4 HA resume budget (#1501)

Adds `testResumeUnreachableWait`/`testResumeRetryBackoff` to `HAState` to
shorten the fencing-lease resume budget — the control that stops a node taking
writable leadership while the fence is unreachable. Both fields are
unexported, default to 0, and `resumeUnreachableTiming()` returns the
production constants on 0. A source-scanning test in
`ha_lease_recovery_chaos_test.go` fails the build if any non-test file in the
package assigns either field. Verified independently: no production assignment
exists.

### 4.5 Frontend audit repair (#1525) and threatfeed gate (#1508)

#1525 is a `package-lock.json`-only `npm audit fix` of four dev-tree
advisories under the pinned Node/npm, with the committed `dist` byte-identical
— no shipped artifact changed. #1508 skips an ns/op benchmark gate under
`-race` and adds a build-tagged file; test-only, and it does not disable a
correctness assertion.

---

## 5. Attack scenarios

**5.1 SEC-PWCHANGE-1, session → durable takeover.** Attacker obtains a Viewer
session cookie for `alice` (stolen browser profile, or an XSS on a panel).
They cannot change `alice`'s password without the current one, and the session
will expire. They script `POST /api/auth/change-password` with
`{"current_password": <guess>, "new_password": "Attacker1234"}` at 60 requests
per minute per source IP, reading 403 as "wrong" and 200 as "done". Nothing
locks the account, nothing rate-limits per account, and — before this change —
nothing is written to the audit ring, so the campaign is invisible and the
eventual success is indistinguishable in the record from a routine rotation.
*After* this change the campaign writes one `auth.password_change.fail` per
attempt, so it is visible to the alerting and compliance tiers; the rate itself
is still only `apiLimiter`-shaped (§6.2).

**5.2 The scenario SEC-BASIC-1 closed, re-tested.** Presenting a TOTP-enrolled
account's password over `Authorization: Basic` to any `/api/` GET, or to the
public `/api/auth/status`. Verified closed: all three `r.BasicAuth()` parse
sites (`ui_middleware.go`, `ui_auth.go`, `events.go`) route through
`verifyUIBasicAuth`, which reserves the per-IP failure budget before spending
a bcrypt, consults the two-tier lockout before verifying, charges failures,
audits them, and refuses the scheme outright for a TOTP-enrolled account —
*after* the password check, so it is not an enrolment oracle. The two
remaining `cfg.VerifyUIUser` request-path callers are the login handler
(which carries the full control set) and the change-password handler
(SEC-PWCHANGE-1).

**5.3 Cluster rate-limit evasion via the extraction.** An attacker spreads
requests across data-plane nodes so that no single node sees enough to trip
its local limit, relying on the cluster broadcast not being applied. Verified
not reachable: the gossip DTOs keep their wire field names, `AllowClusterAware`
and `FreshCount` are unchanged, every production caller shares one limiter
instance, and a stale broadcast degrades to local enforcement (the deliberate
posture) rather than disabling the local budget.

**5.4 Admission bypass via a corrupt persisted mode.** A tampered or truncated
`IPFilterMode` in a restored snapshot. Verified fail-closed: any unrecognised
mode denies all traffic, and the restore path publishes the fully loaded
filter only after `SetMode` + `AddAll`.

---

## 6. Suggested fix

### 6.1 Implemented — audit the refusal (CWE-778)

`apiAuthChangePassword` now writes an audit entry when the presented current
password does not verify:

```go
auditEvent(r, "auth.password_change.fail", username,
    "incorrect current password")
```

This is additive and introduces no new denial path: `username` comes from
`sessionAdmin(r)`, so it is a configured account name needing no bound; the
detail is a fixed string and never carries the presented secret; and the
action name follows the existing `auth.*.fail` family (`auth.login.fail`,
`auth.basic.fail`, `auth.totp.fail`), so existing alerting and the compliance
export pick it up without new wiring. Attempts remain bounded by
`apiLimiter`, so this does not create the audit-write amplifier that
`verifyUIBasicAuth` has to reserve a budget against. No config version is
created, preserving the Category D-sec contract pinned by
`auth_password_change_no_versioning_test.go`.

### 6.2 Not implemented — an optional bound on the attempts, if the owner wants one

**Nothing here is a defect.** #1420 already decided this, and this review
agrees with the decision: charging `loginLimiter` on this endpoint would be
wrong, for the same reason SEC-BASIC-1 declined to charge the per-account
lockout for a TOTP refusal. The endpoint authenticates by **session**, so

- a session holder could lock the legitimate operator out of the login flow as
  a side effect of their own misconfigured script, and
- an attacker who does *not* know the password could lock out any account
  whose session they hold, turning a confidentiality control into a
  denial-of-service primitive.

It is recorded here only because the audit line added in §6.1 changes the
cost/benefit slightly: the campaign is now visible, which is what makes a
bound optional rather than the only defence.

If the owner does want one, the shape that avoids both hazards above is the
one `verifyUIBasicAuth` already established: a **per-IP failure budget** that
locks no account (`basicAuthFailLimiter.Reserve`/`Refund`), claimed before the
bcrypt and refunded on success, so a correctly-configured script is never
throttled. A second, independent option is to route admin-plane
`VerifyUIUser` through the `authcost` governor so the ~80 ms bcrypt on the
data-plane process is bounded process-wide the way the proxy's
`verifyAuthFrom` already is — note its caller contract, that the admission
decision must be taken before and independently of the username comparison
(RISK-008), which is satisfiable here because the username is the session
subject.

Either is a new security control on an existing endpoint and can break a
working operator script, so it belongs in its own reviewed diff with the
owner's call on the budget — not in a scheduled review's patch. Recommended
tests are in §8.2.

---

## 7. Files

| File | Change |
|---|---|
| `ui_auth.go` | `apiAuthChangePassword`: audit the failed current-password verification (SEC-PWCHANGE-1), with the reasoning for not charging `loginLimiter` recorded at the call site |
| `auth_password_change_failure_audit_test.go` | New. Negative, positive and malformed-input regression coverage for the above |
| `docs/engineering/security-reviews/2026-10-10-admission-extraction-and-basic-auth-completeness-window.md` | This review |

Reviewed without change: `internal/admission/engine.go`, `freshness.go`,
`admission.go`, `cluster_ratelimit_wire.go`, `cluster_ratelimit_freshness.go`,
`controlplane_client.go`, `controlplane_snapshot.go`, `ui_cluster.go`,
`metrics.go`, `ui_basic_auth.go`, `ui_middleware.go`, `events.go`,
`internal/lockout/lockout.go`, `internal/shutdown/registry.go`,
`runtime_shutdown.go`, `ha.go`, `ha_failover.go`, `security.go`,
`internal/ssrf/ssrf.go`, `.github/workflows/pr-fast-gate.yml`,
`docs/agent-context/**`, `go.mod`, `Dockerfile`,
`test/e2e/maint-agent/Dockerfile.e2e`.

---

## 8. Required tests

### 8.1 Implemented, with the differential verified

`auth_password_change_failure_audit_test.go`:

- **Negative / authentication.** `TestSECPWCHANGE1_WrongCurrentPasswordIsAudited`
  — a wrong current password must answer 403 **and** leave an
  `auth.password_change.fail` entry naming the account. Also asserts the entry
  carries no password value in any field, and that the refusal mutated
  nothing (the old password still verifies, the attempted one does not).
  Verified failing against the pre-fix handler.
- **Positive control.** `TestSECPWCHANGE1_SuccessIsAuditedAndNotMisreportedAsFailure`
  — the success record is unchanged, a success never emits the failure action
  (which would poison the signal the guard above establishes), and the new
  password verifies.
- **Boundary / malformed input.** `TestSECPWCHANGE1_MalformedAndMissingFieldsAreRefusedBeforeVerification`
  — malformed JSON and empty/missing fields are refused **before** any
  credential verification, so they must not emit the verification-failure
  action; otherwise the audit signal stops meaning "someone guessed".

**The differential.** Against the pre-fix handler (the `auditEvent` call
removed, everything else identical) the negative test fails on exactly its
intended assertion — "a refused current-password verification wrote no audit
entry" — while the positive and boundary tests pass. Against the fixed tree
all three pass. That is the shape a guard should have: only the assertion the
fix is about flips, so the controls are controls and not restatements of it.

Assertions are content-addressed on `Action` + `Object` rather than on ring
length, per the bounded-audit-ring convention; each test swaps the ring and
snapshots `cfg.uiUsers` so shuffled runs do not interact.

### 8.2 Required if §6.2 is adopted

- **Authorization.** A Viewer session may still change its own password; no
  session, or a session for another account, cannot.
- **Boundary.** The budget admits exactly N failures per window and refuses
  the N+1th; the window rolls over.
- **Regression.** A *successful* change refunds its reserved unit, so a
  correctly-configured operator is never throttled; and the per-account
  `loginLimiter` is **not** charged, so a session holder cannot lock the real
  operator out of the login flow.
- **Concurrency.** A concurrent wave of wrong-password attempts from one IP
  reserves atomically — a probe-then-charge pair would let the whole wave pass
  the probe before any bcrypt finishes (the defect
  `basicAuthFailLimiter.Reserve` exists to avoid).
- **Malformed input.** An oversize or non-UTF-8 account name cannot amplify
  writes into the lockout maps or the audit ring.

---

## 9. What else was reviewed and why it appears safe

- **Every `Authorization: Basic` parse site and every `cfg.VerifyUIUser`
  caller** was enumerated, not sampled. Three Basic sites
  (`ui_middleware.go`, `ui_auth.go`, `events.go`), all routed through
  `verifyUIBasicAuth`; three verifier callers in request paths — the
  chokepoint, the login handler, and `apiAuthChangePassword` (SEC-PWCHANGE-1).
  `TestSECBASIC1_VerifyUIUserHasNoOtherRequestPathCaller` enforces that set
  by AST walk and carries a not-vacuous guard, so a fourth caller fails the
  build; it passes unchanged after this review's fix.
- **`UserHasTOTP`** reads `u.totpSecret != ""` under `RLock` against the live
  roster, so the Basic refusal cannot be dodged by a partially-enrolled state
  that reports "no second factor".
- **The `InsecureSkipVerify` inventory** is unchanged by this window. Every
  production instance remains config-gated behind an explicit admin opt-in
  (`auth_oidc.go`, `auth_oidc_flow.go`, `auth_ldap.go`, per-rule override in
  `proxy_tunnel.go`), pin-verified via `VerifyPeerCertificate` (`cdr.go`), or
  a diagnostic with an explicit `MinVersion` (`diagnose.go`), each with a
  scoped `#nosec` carrying its reason. No new instance, and no new suppression,
  appears in the window.
- **Fail-closed SSRF on resolver failure.** `ssrf.PrivateHost` rejects an
  unresolvable host and deliberately does not wrap it in `ErrBlocked` (so a
  resolver outage is not counted as an SSRF refusal) and does not cache DNS
  errors. Confirmed directly — see §10.3.
- **CSRF, body limits and security headers** in `securityMiddleware` are
  untouched: same-origin enforcement on mutating methods, 1 MiB body cap, and
  `nosniff`/`DENY`/`strict-origin-when-cross-origin`.
- **Lockout tiers** are unchanged: 5 failures per (IP, username) and 20 per
  account within a 10-minute window, with `realClientIP` resolution behind a
  configured trusted proxy (RISK-019) so one attacker cannot lock out every
  admin through an L7 proxy that collapses peer IPs.

---

## 10. Residual risk

1. **This series' baseline is hard to find, and the series has a gap.** There
   are two generations of the directory — `docs/security-reviews/` (20 entries,
   last 2026-08-14) and `docs/engineering/security-reviews/` (17 entries, last
   2026-09-24) — with no index in either and no pointer from one to the other.
   The previous entry's recorded head (`b697cf3`) is not reachable in a
   default shallow clone, so this run had to derive the baseline from the
   commit that *added* the previous review. Recommended: an index file naming
   the active directory and the last reviewed head as a resolvable ref
   (a tag, not a short SHA). Until then each scheduled run pays this cost and
   may silently narrow its own window.
2. **`POST /api/auth/change-password` remains unbounded in total** — a
   session holder can guess the account's current password indefinitely,
   rate-shaped only by `apiLimiter` at 60/min/IP. This is a **recorded,
   deliberate trade** (§6.2), not an open finding, and this review did not
   change it. The audit entry added here makes such a campaign *visible*; it
   does not make it *bounded*. Flagged so the next reviewer does not re-open
   it as new.
3. **Admin-plane bcrypt is outside the `authcost` governor.** `VerifyUIUser`
   is reached by the login handler, the Basic chokepoint and the
   change-password handler; only the proxy's `verifyAuthFrom` consults the
   governor. The login and Basic paths are bounded by their own limiters, so
   this is a hardening opportunity, not a finding — but it means admin-plane
   credential verification can still spend data-plane CPU under a bound set
   per-path rather than process-wide.
4. **`VerifyUIUser` returns early for an unknown username** without a dummy
   bcrypt compare, so its timing distinguishes a configured account from an
   unknown one. Pre-existing and bounded by `loginLimiter` on the login path
   and by `basicAuthFailLimiter` on the Basic path; note that the proxy's
   equivalent (`verifyAuthFrom`) *does* equalise the two paths deliberately
   (RISK-008), so the admin plane is the weaker of the two by design rather
   than by oversight. Worth recording, not worth a speculative change.
5. **`govulncheck` could not be re-run independently in this environment** —
   `vuln.go.dev` is refused by the sandbox proxy. The dependency claim was
   verified structurally instead: the compiler in use is `go1.26.9`, the
   resolved module is `golang.org/x/net v0.60.0`, and every builder pin moved
   with it by digest. The advisory list itself is taken from #1592's own
   record, not re-derived.
6. **One root test depends on live DNS and fails in a network-isolated
   environment.** `TestAPIIdPAudit_RedactsWriteOnlyFields` seeds an OIDC
   issuer of `https://example.com`; the handler's SSRF guard resolves it and,
   with no resolver available, correctly fails closed, so the test reports a
   400 that looks like a validation regression. Confirmed to be exactly that
   (`PrivateHost("example.com:443")` →
   `DNS resolution failed: lookup example.com on 8.8.8.8:53: no such host`),
   and neither the test nor the validator is touched by this window. It is a
   test-hygiene risk rather than a product one, and specifically the kind that
   masks a real regression later: a guard test that fails for environmental
   reasons trains its readers to re-run it. Recommended: give it a stubbed
   resolver or a hostname the suite controls.
7. **The window's largest change is still a refactor, and refactors of this
   kind are only as good as their differential tests.** The equivalence
   argument in §4.1 rests on a line-level diff plus the package's own
   ownership and boundary tests; it does not rest on a behavioural oracle
   replaying pre- and post-extraction admission decisions against the same
   input corpus. Such an oracle would be the stronger control, and does not
   exist for this move.

---

## 11. Verification performed

| Check | Result |
|---|---|
| `go test -race -count=1 ./internal/admission/... ./internal/ssrf/... ./internal/connlimit/...` | **pass** (2.4 s / 18.8 s / 1.1 s) |
| `go test -race -run 'SECPWCHANGE1\|TestAPIAuthChangePassword\|SECBASIC1' .` | **pass** — the 3 new tests, the no-versioning regression test, and all 11 existing SEC-BASIC-1 tests |
| Same, against the pre-fix handler | negative test **fails** on its intended assertion, controls pass (§8.1) |
| `go test -race -run 'Admission\|IPFilter\|RateLimit\|RLExempt\|FastGate\|ClusterRateLimit\|Security\|SSRF\|RequireRole\|Audit' .` | **pass except** `TestAPIIdPAudit_RedactsWriteOnlyFields`, an environment-only failure proven to be absent DNS (§10.6); **no data races** |
| `python3 docs/agent-context/check.py --self-test` | **pass** — 108 blocks, 117 route edges, 450 links, 21 negative controls rejected |
| `gofmt -l`, `go vet .` | clean |
| `govulncheck ./...` | **not run** — `vuln.go.dev` refused by the sandbox proxy (§10.5) |

These are focused checks selected for the changed behaviour, not a complete
CI verdict: the full module suite, the Deep gate, CodeQL and the hosted review
gates have not run against this tree. A passing local check is not a passing
merge gate.
