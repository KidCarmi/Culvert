# Security Regression Review — CHAOS-47 identity-backend availability, MCP tenant isolation, CHAOS-25 panic containment (window `6a2960e` → `d2c5a51`)

> **Reviewer role:** Security Regression Engineer (AppSec / Secure Code Review / Product Security)
> **Review date:** 2026-08-07
> **Baseline:** `6a2960e` — head of the previous review's window
> (`docs/security-reviews/2026-08-06-mcp-observe-telemetry-panic-containment-async-log-window.md`)
> **Head:** `d2c5a51` (`main`)
> **Scope reviewed:** every code-bearing change in the window — 19 first-parent
> merges (PRs #876–#1072), 104 files, +12,035 / −257.
>
> **Method.** Prioritised by *live blast radius*, not diff size:
>
> 1. **Enabled-by-default authentication code that changed** — the legacy LDAP
>    and OIDC proxy-auth backends, which run on every request that reaches the
>    gate, and the new process-wide identity-backend health record they now
>    drive.
> 2. **Enabled-by-default enforcement code that changed** — the Stage-1 auth-rule
>    resolver (subject-CIDR precompute, schedule-timezone cache), the YARA regex
>    ReDoS harness (runs on every scanned body), the HA standby sync/promote
>    path, the backup-restore tarball reader, and the signed SaaS feed fetcher.
> 3. **New operator-activatable surface** — the MCP Gateway QUAL-4 node-local
>    policy source and the QUAL-5 tenant-isolation override. Reviewed for
>    *inertness of the default* first, then fail-closed correctness.
> 4. **Privileged host tooling** — the maintenance-agent installer's TOML
>    extraction and `proxy_repo` ↔ `image_allowlist` binding check.
> 5. **Admin-UI surface** — new API fields, checked for RBAC drift and
>    sensitive-value leakage into viewer-role responses.
>
> The `internal/mcpacceptance` package and `cmd/mcp-observe-acceptance` (≈3,500
> new lines) were confirmed **not reachable from the production binary** — no
> file outside those two trees imports them — and were therefore reviewed as
> test tooling, not runtime attack surface.

---

## Executive Summary

**Three findings, all fixed in this change:**

- **SR-…-01 (HIGH)** — an unauthenticated, remotely-triggerable denial of
  service against the **entire proxy authentication plane** on deployments
  using LDAP/Active Directory proxy auth, introduced by the otherwise-sound
  CHAOS-47 identity-backend availability work (PRs #1064 / #1061).
- **SR-…-01b (HIGH)** — the same gate held **open** rather than armed: an
  answered-but-rejected credential consumed each half-open recovery probe
  without clearing the cooldown, so one attacker could hold a *recovered*
  backend in a permanent outage. Present on the **OIDC** leg as shipped in
  `fdc62fc`, and on the first version of this PR's LDAP fix. Found by Codex
  review on PR #1077.
- **SR-…-02 (MEDIUM, detection)** — the **CodeQL SAST gate has executed zero
  queries** since `4251a13`, failing as a configuration error rather than a
  finding.

Everything else in the window is either neutral or a net security improvement.
There is **no authentication bypass, no authorization bypass, no default-allow,
no missing signature validation, no weakened certificate validation, no new SSRF
or open-redirect primitive, and no secret exposure.**

The finding is notable for *how* it survived: the identical vulnerability class
was found on the **OIDC** leg during review of the same feature and fixed in
`fdc62fc` ("an unauthenticated attacker could trip the provider-wide cooldown
with a single malformed token"). That commit **also touched `auth_ldap.go`** —
but only to silence an `errcheck` lint on a `defer Close`. The structurally
identical hole one file over was not carried across. This is the classic
asymmetric-hardening failure: a class fixed on one instance and left open on its
twin. SR-…-01b then demonstrated the same lesson in the other direction — the
first fix for the LDAP leg was itself incomplete, and completing it exposed the
matching gap in the OIDC code that had been treated as the reference
implementation.

SR-…-02 is a different kind of finding: nothing in the product regressed, but
the mechanism that would have *caught* a regression stopped running silently.
PRs #1069 and #1070 in this same window were merged as fixes for CodeQL alerts
#265 and #219; both are genuine tightenings on manual review, but the scanner
meant to confirm them never executed. Re-run CodeQL on `main` after this lands
to re-baseline the alert set.

---

## Security Findings

### SR-2026-08-07-01 — HIGH — Attacker-provokable LDAP bind result arms the provider-wide authentication cooldown

| | |
|---|---|
| **Severity** | **HIGH** |
| **CWE** | CWE-754 (Improper Check for Unusual or Exceptional Conditions) → CWE-400 (Uncontrolled Resource Consumption) |
| **OWASP** | A04:2021 Insecure Design |
| **Regression risk** | **Introduced in this window** (`6a2960e`..`d2c5a51`) |
| **Affected assets** | Proxy authentication plane (all users), organisation-wide egress |
| **Status** | **Fixed in this change** |

#### The defect

CHAOS-47 added `authProbeGate` (`auth_backend_health.go`): when an identity
backend is judged **unreachable**, a **provider-wide** gate arms for
`authBackendProbeCooldown` (3 s), during which *every* authentication attempt is
denied **without contacting the directory**, and exactly one probe is admitted
per cooldown. That is the correct response to a directory that is genuinely
down: it prevents a stampede of 10-second dial timeouts.

`LDAPAuth.Verify` armed that gate on **every** error returned by `verify()`.
And `verify()`'s step-2 user-bind branch classified **any result code other than
49 (`invalidCredentials`) as infrastructure**:

```go
// auth_ldap.go — before
if err := conn.Bind(userDN, password); err != nil {
    if !ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
        return false, fmt.Errorf("user bind: %w", err)   // → gate.recordUnavailable()
    }
    return false, nil
}
```

A non-49 result code is **not** evidence that the directory is unreachable — it
is proof of the opposite: the directory answered. And *which* code comes back is
chosen by the state of the **one account being bound**, which is under the
control of whoever is attempting the bind.

#### Attack scenario

**Preconditions**
- Culvert configured with LDAP/AD proxy authentication (`auth_ldap.go` path).
- The attacker can reach the proxy port and knows **one** valid username.
  Usernames are typically email addresses or `first.last` — not a secret.
- No authentication is required to attempt authentication.

**Execution**
1. The attacker picks a known username and brute-forces it past the directory's
   own lockout threshold (5–10 attempts on a default AD/OpenLDAP policy). No
   password knowledge is needed — failing is the goal.
2. From that point the directory answers binds for that account with a
   non-49 code. OpenLDAP with the `ppolicy` overlay returns **53**
   (`unwillingToPerform`) or **19** (`constraintViolation`); FreeIPA returns
   **53** for a locked or expired principal. The same applies without any
   brute-force to a **disabled** account, an **expired** password, or — with a
   broad `user_filter` — any non-person entry with no bindable credential
   (**48**, `inappropriateAuthentication`).
3. Each such attempt calls `gate.recordUnavailable()`, arming the gate for 3 s
   **for every user of the proxy**.
4. The attacker repeats every ~2 s. Because the gate re-arms on *grant*, and the
   attacker's request rate dominates, the attacker also wins most of the single
   probes the gate releases.

**Result:** sustained, near-total denial of proxy authentication. Legitimate
users receive `407` without the proxy ever contacting a perfectly healthy
directory. On an in-line Secure Web Gateway, loss of authentication is loss of
egress for the whole organisation.

**Measured.** The regression test added here (`TestLDAP_ConcurrentAccountRejectionsNeverGate`)
runs 8 attacker goroutines against 8 legitimate ones. On the pre-fix code:

```
1400 legitimate authentication attempt(s) were denied without reaching the directory
concurrent account rejections leaked into backend health:
  {Unavailable:1600 GatedDenials:0 Degraded:true Backend:ldap ...}
```

**87.5 % of legitimate authentications denied** at modest attacker concurrency.
The same run additionally lights the `idp_unreachable` alert and drives the
`identity_backend` operator-contract row to `fail`, so the attack **also
manufactures a false directory-outage page** — the operator is sent to
investigate a healthy directory while the proxy is the thing failing.

**Exploitability:** High — unauthenticated, no special position, single known
username, trivially scriptable.
**Likelihood:** High where LDAP proxy auth is deployed (the common enterprise
configuration).
**Impact:** High (availability); no confidentiality or integrity impact — the
posture stays fail-**closed** throughout, so nothing is wrongly admitted.

#### Why this is a regression and not a pre-existing issue

Before this window, a non-49 bind error returned `false` and was cached under
that one `(user, password)` key. The blast radius was exactly one credential
pair. The cross-user gate is new.

#### Fix

Split "the directory could not be reached" from "the directory answered about
this account", mirroring `errIntrospectClient` on the OIDC leg exactly:

- **`ldapUserBindIsUnreachable(err)`** (`auth_ldap.go`) — a server-produced RFC
  4511 result code means the directory is **reachable**, so it must not gate.
  Unreachable is: (a) not an `*ldap.Error` at all, (b) a go-ldap client-space
  code (`ErrorNetwork` 200 … `ErrorEmptyPassword` 206), or (c) `LDAPResultBusy`
  (51) / `LDAPResultUnavailable` (52) — server-wide back-off signals no single
  account's state can provoke, the direct analogue of the HTTP 429/408 carve-out
  `isIntrospectClientError` already makes.
- **`errLDAPAccountRejected`** — `verify()` wraps a reachable-but-rejected bind
  in this sentinel.
- **`LDAPAuth.noteVerifyError`** — the single place the gating policy is applied.
  An account rejection denies the request closed, is **not cached** (so an
  account the directory unlocks authenticates on its very next attempt), and does
  **not** touch the gate or the health record. Everything else gates exactly as
  before.

The fail-closed posture is unchanged on every path: **every** branch still
denies the in-flight request. Only the *blast radius* changed.

#### SR-2026-08-07-01b — the same gate, held open instead of armed

Found by Codex review on PR #1077, on the first version of the fix above.
**Severity HIGH; affects the OIDC leg as shipped in `fdc62fc` as well.**

Declining to *arm* the gate is only half the contract. The gate is half-open:
after the cooldown elapses it grants exactly **one** probe and immediately
re-arms. The attacker is by construction the caller generating the most
traffic, so they are also the one most likely to **win that probe**.

If a directory-answered rejection merely avoided arming the gate — without
recording the reachability it proves — then:

1. a genuine outage (or blip) arms the gate;
2. the directory recovers;
3. the cooldown elapses and the attacker's locked-account bind takes the probe;
4. the rejection leaves `down` still set, and step 3's grant has already
   re-armed `until`;
5. every other user is denied for another full cooldown — and it repeats.

A three-second network blip becomes an **indefinite** outage, sustained by a
client looping on one locked account. The precondition is weaker than it looks:
a transient reachability failure is inevitable in production, and the attacker
only needs to be attempting authentication when it happens.

**The OIDC leg had the identical defect.** `ResolveIdentity`'s
`errIntrospectClient` branch returned without `recordReachable`, so a caller
with one malformed token could hold a recovered IdP gated the same way. That
code shipped in `fdc62fc` and is therefore a **pre-existing** defect this PR
also closes — fixing only LDAP would have repeated exactly the asymmetric
hardening failure this whole report is about.

**Fix.** Both legs now call `recordReachable()` + `noteAuthBackendReachable()`
on the answered-but-rejected path. This is precisely what `recordReachable` is
documented for — *"the backend answered — authoritatively, in either direction
— so it is up"*. An HTTP status code and an LDAP result code are both answers.

No security property is relaxed: clearing the gate only means subsequent
requests dial a backend that has demonstrably just responded, which is the
normal pre-CHAOS-47 behaviour. If the backend is only partially healthy (binds
answer, searches fail), the next search failure re-arms the gate immediately, so
the state is self-correcting.

Pinned by `TestLDAP_AccountRejectionClearsAnArmedCooldown`,
`TestLDAP_AttackerCannotHoldTheGateOpen` and
`TestOIDCAuth_4xxClearsAnArmedCooldown` — all three drive the cooldown from the
`authProbeGate.now` injected clock rather than sleeping, and all three fail
without the fix.

#### Deliberately left gating (reviewed, accepted)

The **service-bind** and **search** branches still arm the gate. Neither is
attacker-account-scoped: the service credential is operator-owned, and the
search filter is built with `ldap.EscapeFilter(username)`, so a client cannot
inject filter metacharacters to provoke a search fault. A wrong service password
is a configuration fault where the anti-stampede gate is the desired behaviour.

---

### SR-2026-08-07-02 — MEDIUM — The CodeQL SAST gate has run no queries since `4251a13`

| | |
|---|---|
| **Severity** | **MEDIUM** (detection capability, not a product defect) |
| **CWE** | CWE-1127 (Compilation with Insufficient Warnings or Errors) — analogue for a disabled analysis gate |
| **OWASP** | A09:2021 Security Logging and Monitoring Failures |
| **Regression risk** | **Introduced in this window** (PR #1024, commit `4251a13`) |
| **Status** | **Fixed in this change** |

`github/codeql-action` is a monorepo: `init`, `analyze` and `upload-sarif` ship
from one release and are **not** cross-compatible — `analyze` refuses a database
a different version initialised. Dependabot treats each sub-action *path* as its
own ecosystem, so PR #1024 bumped **only `analyze`** (`e4fba86` → `f205ea1`) and
left `init` behind. Every run since ends:

```
Loaded a configuration file for version '4.37.3', but running version '4.37.4'
CodeQL job status was configuration error.
```

The job dies **before running a single query**. It is red, so it is not
invisible — but it is red for a reason that reads as infrastructure flake, and
no finding it would have produced was ever produced. `7130f66` (*"ci: align
CodeQL action revisions"*) shows the same split had already happened once and
was corrected by hand, so it recurs on its own.

**Fix.** `init` realigned to `f205ea1c`, plus `codeql_action_pin_test.go` as an
anti-drift wall in the repo's established idiom:
`TestCodeQLActionRevisionsAreAligned` (every `github/codeql-action/*` pin in the
workflow must resolve to one commit SHA — verified to fail on the pre-fix file)
and `TestCodeQLActionPinsAreImmutable` (no CodeQL step may regress to a mutable
`@v3`/`@main` ref; these jobs hold `security-events: write`). The invariant is
pinned on the **SHA**, not the version, because the trailing `# v3` comments
Dependabot leaves are stale and disagree with the actual release.

**Not done here (policy, not defect):** grouping the three `codeql-action` paths
in `.github/dependabot.yml` so they cannot split at the source. Flagged on the
PR for the maintainer's decision.

---

## Verified Safe — reasoning recorded

Each of these was examined specifically for a weakening and found not to be one.

**Backup-restore zip-slip guard (`restore.go`, CodeQL alert #219).** The
per-component `part == ".."` loop was replaced with
`strings.Contains(hdr.Name, "..")`. This is **strictly broader** — it also
rejects names like `foo..bar` that the old guard admitted. Combined with the
retained absolute-path and duplicate-entry guards, traversal remains blocked.
Backup entry names are system-controlled filenames, so the over-rejection has no
functional cost. **Tightening.** (CWE-22)

**Signed SaaS feed SSRF guard (`saas_feed_download.go`, CodeQL alert #265).** An
inline scheme + host equality check was added immediately before `f.client.Do`,
*in addition to* the existing `validateFeedURLContract` call on every hop. This
is defence-in-depth placed where CodeQL can trace it, per the repo's documented
SSRF convention. Host comparison uses `cur.Hostname()` against the official
constant — exact match, no suffix logic. Log output is `strings.ReplaceAll`-
sanitised at the call site. **Tightening.** (CWE-918)

**MCP Gateway tenant isolation (`internal/mcp/policy/engine.go`, QUAL-5).** A
new step-6 override denies when the authenticated tenant does not own the
addressed server. The binding is byte-exact, an **empty** `OwnerScope` fails
**closed** (an unscoped server is never "owned by everyone"), and it is the
**first** server-level override — so a cross-tenant request can never be
laundered into an ALLOW by a later user rule, and never learns the foreign
server's verification or enabled state (no cross-tenant existence oracle). Safe
even if `Principal.Tenant` were empty, because the `Owner == ""` clause fires
first. **Tightening.** (CWE-639)

**YARA ReDoS harness hoisted per-scan (`internal/yara/regexrunner.go`).** A cost
change, not a policy change, and the fail-closed contract survives:
- The budget stays **per regex string** — the timer is re-armed for each
  string's full timeout. A whole-scan budget would have failed closed on large
  bodies with many individually-fine strings, i.e. blocked clean traffic.
- Timeout still resolves through the unchanged `yaraTimeoutResult`, so the
  admin-selected `on_timeout` posture is honoured and the default remains block.
- **Saturation is still evaluated per match**, not per scan, so a scan that
  started before the engine saturated cannot keep matching afterwards.
- The `yaraInflight` charge tracks the **match**, not the worker, released by
  the parent on a normal result and inherited by the worker on a timeout (CAS
  guarantees exactly one release). Holding it for the worker's lifetime would
  have blocked *clean* concurrent scans under the default fail-closed posture —
  that specific inversion is pinned by `TestRegexRunner_IdleWorkerHoldsNoSlot`.
- No stale-result cross-contamination: on timeout the runner is abandoned and
  `c.runner` cleared, so the buffered result the wedged worker eventually writes
  is never read by a subsequent match. Both channels are buffered, so an
  abandoned worker cannot leak.
- Contained per-match panics resolve through the **same** posture as a timeout
  (no verdict ⇒ not "clean"), and only the offending string is affected.

**CHAOS-25 HA panic containment (`ha.go`).** The critical question was whether
containment can manufacture a split brain. It cannot:
- A panicking sync round deliberately does **not** advance `syncFailCount`.
  This is the load-bearing decision — the bundle is leader-supplied, so a
  deterministic apply-path panic repeats every tick, and charging those rounds
  toward `haStandbyMaxFail` would auto-promote a standby whose only problem is
  its own parser, against a healthy leader.
- The silence that would otherwise create is paid for: crash record, the
  `sync_panics` status field, and a fire-once `ha_sync_panic` alert re-armed by
  the next healthy round.
- A contained panic in `onPromote` takes the **same** branch the pre-existing
  `promoteErr != nil` path already took (`promoted.Store(false)`, stay standby).
  It introduces no new post-promotion state, and the unkept lease grant expires
  on its TTL as already documented.
- `onMaxFail` returning `s.h.IsLeader()` instead of unconditional `true` is a
  **fix**: the loop no longer exits on a failed promotion, which previously
  ended both replication and leader monitoring on a node that never became
  leader.

**Stage-1 subject-CIDR precompute (`authpolicy.go`, `policy.go`).** Matching is
semantically identical: the fast path is `clientAddr != nil && net.Contains(addr)`,
byte-for-byte what `matchIPOrCIDRAddr` computes for a CIDR value. Any value that
fails `ParseCIDR` leaves a `nil` slot and falls back to the original allocating
path, so correctness never depends on the precompute being populated. The
`nets` field is unexported (never serialised) and is cleared by
`copyPolicyRuleForPublication`, so a copy can never carry a net parsed from
since-edited `Values`. `sortLocked` mutates only freshly cloned rules before
publication, so there is no race with the hot path. Empty value lists still fail
closed.

**Schedule-timezone cache (`policy.go`).** `authScheduleParseable` moved from a
direct `time.LoadLocation` to the memoising `scheduleLocationResolved`, which
returns the parse **outcome** alongside the location. The Stage-1 gate still
fails closed on an unparseable timezone — the whole reason the tri-state was
introduced rather than reusing `scheduleLocation`, which silently substitutes
UTC. No other consumer of `scheduleLocCache` type-asserts the old
`*time.Location` value.

**CHAOS-47 core design (`auth_backend_health.go`).** Sound apart from the LDAP
classification above. Only an *authoritative* answer is cached; a reachability
failure denies but is not remembered. `allow()` re-arms on **grant**, not on
result, so a probe that never reports back cannot leave the gate open. Recovery
is evidence-based — an observed reach, never elapsed time. The
`idp_unreachable` producer correctly gates on `HasSubscriber` per the repo's
per-request-alert contract. CWE-117 sanitisation is applied once at the point
values enter shared state.

**Sensitive-value handling in the new operator-contract row
(`diagnostics.go`).** `checkIdentityBackend` is a **viewer-role** surface and
deliberately omits `snapshot.Err` — the cause text names the configured LDAP URL
or IdP host. The cause reaches only the admin-scoped sinks (the process log and
the webhook alert). Correct per the standing no-sensitive-values guardrail.

**New admin API fields.** `/api/stats` gains `processLogBackpressure` (a
counter); `/api/mcp/overview` gains a `policy` block whose fields are revision,
canonical hash, rule count and default action — no rule bodies, no secrets;
`/api/cdr/instances` gains circuit-breaker/health state. All are read-only
counters or state labels on existing role-gated routes, with no new route and
therefore no `uiRoutes` metadata drift.

**Maintenance-agent installer (`packaging/culvert-maint/install.sh`).** Both
changes tighten. `extract_toml_string` now handles TOML **literal** (single-
quoted) strings, fixing a case where surrounding quote characters leaked into
the extracted `image_allowlist` and silently defeated its `^...$` anchoring.
`check_proxy_repo_matches_allowlist` replaces a substring heuristic — which
would wrongly pass a repo that is merely a substring of the allowlist's literal
text — with a real regex match against a synthetic digest-pinned ref, and now
runs even when `image_allowlist` is unset (previously skipped, silently allowing
a custom `proxy_repo` that the defaulted allowlist can never match). Both
failure modes are `die`, i.e. fail-closed.

**`docker-compose.yml`.** `depends_on: clamav` became `condition:
service_healthy`. The proxy no longer accepts traffic during the ClamAV
signature-download window. Availability cost on first boot; security-positive.

**MCP QUAL-4 node-local policy (`mcp_policy.go`, `mcp_observe_startup.go`).**
Disabled by default (absent file ⇒ no snapshot, `Deps.Policy` nil). A
present-but-invalid source **fails activation closed** — nothing binds, no
partial snapshot is published. Publication is post-validation and atomic. A
non-Gateway capability is rejected so the Management surface can never be armed
from this path. `invalidateMCPActivationOnStartupFailure` clears policy,
inventory and telemetry when the listener then fails to bind, closing the
window where the admin surface advertised an active policy for a listener that
was not running. No executor, upstream client or credential broker is composed,
so an evaluated ALLOW still returns `execution_state=not_implemented`.

**Dependency bumps.** `go.mod`/`go.sum` deltas and the workflow-pin bumps
(`actions/checkout`, `codeql-action`) carry no trust-material change; no
signing keys, trusted roots or pinned identities were touched.

---

## Regression Analysis

| Property | Before window | After window (+ this fix) |
|---|---|---|
| LDAP: wrong password | deny, cached | deny, cached (unchanged) |
| LDAP: locked/disabled/non-bindable account | deny, cached for that credential | deny, **not** cached, **no** provider-wide gate, **clears** an armed gate |
| LDAP: directory unreachable | deny, **cached** (stale lockout for full TTL) | deny, not cached, provider-wide gate + probe |
| LDAP: server busy/unavailable | deny, cached | deny, not cached, gate |
| OIDC: inactive token | deny, cached | deny, cached (unchanged) |
| OIDC: 4xx introspection | deny, cached | deny, not cached, **no** gate, **clears** an armed gate |
| OIDC: IdP unreachable / 5xx | deny, **cached** | deny, not cached, gate |
| Cross-tenant MCP server address | (no check) | **DENY** `MCP.AUTH.TENANT_MISMATCH` |
| Tarball entry containing `..` | rejected per-component | rejected on any substring |
| YARA regex overrun | fail closed per string | fail closed per string (unchanged) |

No security property was relaxed anywhere in the window. The one property that
*was* relaxed by the CHAOS-47 work — the blast radius of a single failed bind —
is restored by this change.

---

## Files

| File | Change |
|---|---|
| `auth_ldap.go` | `errLDAPAccountRejected`, `ldapUserBindIsUnreachable`, `noteVerifyError`; step-2 bind branch reclassified |
| `auth_oidc.go` | `errIntrospectClient` branch now records observed reachability (SR-…-01b) |
| `auth_ldap_gate_test.go` | **new** — classifier, boundary, wiring, concurrency and regression tests |
| `auth_oidc_test.go` | `TestOIDCAuth_4xxClearsAnArmedCooldown` |
| `.github/workflows/codeql.yml` | `init` realigned to the analyze/upload-sarif revision (SR-…-02) |
| `codeql_action_pin_test.go` | **new** — CodeQL action pin alignment + immutability walls |
| `docs/security-reviews/2026-08-07-…-window.md` | this report |

---

## Required Tests — delivered

| Class | Test |
|---|---|
| Positive (must gate) | `TestLDAP_ReachabilityFailureStillArmsCooldown` — 6 sub-cases: transport failure, busy, unavailable, dial refused, service-bind failure, search failure |
| Negative (must **not** gate) | `TestLDAP_AccountRejectionDoesNotArmCooldown` — 25 consecutive rejections leave the gate open and the health record clean |
| Regression | Both of the above **fail on the pre-fix code** (verified by reverting the branch: 1400/1600 legitimate attempts denied, `Unavailable:1600`, `Degraded:true`) |
| Boundary | `TestLDAPUserBindIsUnreachable_ClientSpaceBoundaries` — floor−1, the whole 200–206 client space, and code 4096 above the ceiling |
| Malformed / unclassifiable input | `TestLDAPUserBindIsUnreachable_Classification` — plain `net.OpError`, `context.Canceled`, opaque `errors.New` all default to the conservative branch |
| Error-wrapping integrity | `TestLDAPUserBindIsUnreachable_ThroughWrapping` — single and double `%w` wrapping preserves the decision |
| Concurrency | `TestLDAP_ConcurrentAccountRejectionsNeverGate` — 8 attackers × 8 victims × 200 rounds under `-race` |
| Half-open recovery (01b) | `TestLDAP_AccountRejectionClearsAnArmedCooldown`, `TestLDAP_AttackerCannotHoldTheGateOpen` (10 cooldown windows), `TestOIDCAuth_4xxClearsAnArmedCooldown` — injected clock, all three fail without the fix |
| CI trust surface (02) | `TestCodeQLActionRevisionsAreAligned` (fails on the pre-fix workflow), `TestCodeQLActionPinsAreImmutable` |
| Authentication | `TestLDAP_EmptyPasswordStillShortCircuits`, `TestLDAP_AccountRejectionIsNotCached`, `TestLDAP_GateRecoversOnObservedReach` |

`go test -race -count=1` green on the auth surface; full `main` package suite
green (`ok … 119.7s`); `go vet` clean; targeted `golangci-lint`
(cyclop/gocritic/errcheck/revive/gosec) reports nothing on `auth_ldap.go`;
shuffled `-count=2` re-run green.

---

## Residual Risk

1. **The IdP-registry OIDC path (`auth_oidc_flow.go`) has no outcome cache and
   therefore no gate.** It is un-poisonable and un-DoSable by this class, but
   also un-protected against the stampede CHAOS-47 addresses for the legacy
   path. Already tracked as **CHAOS-49**; unchanged by this work.

2. **A genuinely misconfigured service account still gates.** A wrong or expired
   `bind_dn` password arms the cooldown on every attempt. This is intentional —
   it is operator-controlled, not attacker-controlled, and the anti-stampede
   behaviour is desirable there — but it means an operator credential rotation
   gone wrong produces a full authentication outage rather than a slow one. The
   `identity_backend` operator-contract row names the condition.

3. **The 3-second cooldown remains a compile-time constant.** A single
   transient network error still denies all users for up to 3 s. Accepted as
   designed; documented here so it is a known property rather than a surprise.

4. **A cached negative still outlives a password change.** Unrelated to this
   window: a user who fixes their password waits out `CacheTTL` (default 5 min)
   for the *wrong-password* entry to expire. Pre-existing, unchanged.

5. **A partially-healthy backend oscillates.** After SR-…-01b, a backend that
   answers binds but fails searches will have its gate cleared by each bind and
   re-armed by each search failure. The state is self-correcting and always
   fails closed, but the `culvert_auth_backend_unavailable` gauge will flap
   under that specific fault. Accepted; noted so it is not mistaken for a bug.

6. **`ldapUserBindIsUnreachable` depends on go-ldap's code space.** If a future
   go-ldap release adds client-side error codes outside 200–206, they would be
   misclassified as "server answered". The failure mode is a lost gate (a
   stampede), never a bypass; the boundary test will not catch it automatically.
   Worth re-checking on a go-ldap major bump.
