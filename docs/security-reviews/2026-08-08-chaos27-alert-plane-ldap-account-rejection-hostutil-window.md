# Security Regression Review — CHAOS-27 alert-plane bounding, LDAP account-rejection split, hostutil fast path (window `d2c5a51` → `1c24311`)

> **Reviewer role:** Security Regression Engineer (AppSec / Secure Code Review / Product Security)
> **Review date:** 2026-08-08
> **Baseline:** `d2c5a51` — head of the previous review's window
> (`docs/security-reviews/2026-08-07-chaos47-identity-backend-mcp-tenant-isolation-window.md`)
> **Head:** `1c24311` (`main`)
> **Scope reviewed:** every code-bearing change in the window — 8 first-parent
> merges (PRs #1073–#1081), 17 commits, 45 files, +5,312 / −274.
>
> **Method.** Prioritised by *live blast radius*, not diff size:
>
> 1. **Enabled-by-default authentication code that changed** — the LDAP
>    user-bind result-code classifier and the OIDC 4xx branch, both of which now
>    decide whether a per-request authentication failure is allowed to arm (or
>    is required to clear) the CHAOS-47 provider-wide cooldown. This is the same
>    file pair that produced the previous window's two HIGH findings, so it was
>    re-reviewed against the *library's actual* error space rather than against
>    the code's description of it.
> 2. **Enabled-by-default parsing code that changed** — `hostutil.StripHostPort`,
>    which normalises the destination host for the threat feed, DPI scanner,
>    scan-exclusion matcher, autoexclude cache and traffic redactor. A
>    normalisation change here is the classic policy-bypass primitive, so the
>    claimed equivalence was verified by differential fuzzing, not by reading.
> 3. **Egress that changed shape** — the alert plane's webhook delivery client
>    moved from per-attempt to process-wide and pooled. Reviewed specifically
>    for whether connection reuse can outlive or sidestep the SSRF dial guard.
> 4. **Alert/detection surface** — the CHAOS-27 dedup cap (can it silence a real
>    alert?) and the CHAOS-47 alert-event rename (does every subscriber survive
>    it?). **The one finding is here.**
> 5. **Privileged/operator surface** — the `cli` compose service gaining
>    `CULVERT_CA_PASSPHRASE`, reviewed as a secret-scope change.
> 6. **CI trust surface** — the CodeQL action pin realignment, which closes the
>    previous window's SR-…-02 detection finding.
>
> The `internal/mcpacceptance` additions (≈1,900 new lines this window) were
> re-confirmed **not reachable from the production binary** — no file outside
> `internal/mcpacceptance/` and `cmd/mcp-observe-acceptance/` imports the
> package — and were therefore reviewed as CI tooling, not runtime attack
> surface.

---

## Executive Summary

**One finding, fixed in this change:**

- **SR-2026-08-08-01 (MEDIUM, detection)** — the CHAOS-47 alert-event rename
  (`idp_unreachable` → `identity_backend_unreachable`, PR #1075/#1078) shipped a
  migration that runs **only when the webhook store is loaded from disk**. Two
  supported paths admit an event list without passing through that load —
  **configuration import** (replaying a backup exported from a pre-rename build)
  and the **webhook admin API**, which applies no event-name allowlist. Either
  one silently restores the retired name, and because `HasSubscriber` and
  `Dispatch` compare event names byte-for-byte, the webhook is then **never
  delivered to**. The lost subscription is the one that fires when the external
  identity backend is unreachable and proxy authentication is failing closed —
  i.e. during a full egress outage.

Everything else in the window is either neutral or a net security improvement.
There is **no authentication bypass, no authorization bypass, no default-allow,
no missing signature validation, no weakened certificate validation, no new SSRF
or open-redirect primitive, and no secret exposure.**

Two things are worth recording as *near misses that held*:

- The LDAP classifier's client-error range (`ldapClientErrorFloor` = 200 …
  `ldapClientErrorCeil` = 206) includes `ErrorEmptyPassword`, which go-ldap
  raises **client-side, without contacting the directory**, whenever `Bind` is
  called with an empty password. Had that reached `conn.Bind`, an
  unauthenticated attacker holding one valid username could have armed the
  provider-wide cooldown at will with `Basic base64("user:")` — the third
  instance of the exact vulnerability class the previous two windows fixed.
  It does not reach it: `LDAPAuth.Verify` rejects `password == ""` before the
  cache, the gate, and the dial (`auth_ldap.go:176`). The guard is load-bearing
  for a reason that is not written down where it is enforced; see
  *Residual Risk*.
- The alert delivery client became **shared and pooled**. Connection reuse is a
  standard way to outlive an SSRF check, and it does not here — `ssrf.SafeDialContext`
  runs on every *dial*, and a pooled connection is by construction a connection
  to an address that already passed the check, so reuse cannot reach an address
  that was never validated. DNS rebinding is likewise unreachable *through the
  pool*: the pooled socket goes to the validated (public) IP, not to whatever
  the name now resolves to.

The finding is notable for the same reason the previous window's was: a change
was made correctly at **one** entry point and not carried across to its twins.
Last window it was a class fixed on the OIDC leg and left open on LDAP. This
window it is a migration applied to the load path and not to the two write paths
that feed the same field. The recurring shape is *"the fix went where the bug
was observed, not where the data enters."*

---

## Security Findings

### SR-2026-08-08-01 — retired alert-event name is silently reintroduced by config import and the webhook API, dropping the identity-backend-outage subscription (MEDIUM, **fixed in this change**)

**Where.** `internal/alerts/store.go` — `legacyEventNames` / `Init` (migration
present), `Add` / `Update` (migration absent).

**What changed in the window.** PR #1075/#1078 renamed the CHAOS-47 alert event
from `idp_unreachable` to `identity_backend_unreachable`, because "IdP" is
reserved in Culvert's vocabulary for the federated Identity Provider registry
(`auth_idp.go`), a different subsystem this alert does not cover. The rename was
correctly recognised as subscription-breaking, and a migration was added:

```go
// Init, after json.Unmarshal:
for i := range as.hooks {
    for j, ev := range as.hooks[i].Events {
        if renamed, ok := legacyEventNames[ev]; ok {
            as.hooks[i].Events[j] = renamed
        }
    }
}
```

**The defect.** `Init` is not the only way an `Events` list enters the store.
Both writers admit one verbatim:

| Entry point | Caller | Migrated before the fix |
| --- | --- | --- |
| `Store.Init` | startup load of `alert_webhooks.json` | ✅ |
| `Store.Add` | `POST /api/alerts/webhooks` **and** config import (`ui_config.go:1167` → `globalAlertStore.Add(wh)`) | ❌ |
| `Store.Update` | `PUT /api/alerts/webhooks?id=…` | ❌ |

There is **no event-name allowlist** anywhere on the API path
(`apiAlertsWebhooks`, `ui_security.go:33`), so an arbitrary string is accepted
and stored. Matching is exact in both consumers:

```go
// HasSubscriber and Dispatch, identically:
if ev == event || ev == "*" { … }
```

so a hook left on `idp_unreachable` matches nothing. It is not merely
undelivered — it is **invisible as undelivered**: the admin UI checkbox is keyed
on the current name (`static/index.html`, `value="identity_backend_unreachable"`),
so the box renders **unchecked** for a hook that *is* persisted and *does* appear
in the list. The operator's UI says "not subscribed", the stored config says
subscribed, and neither says the subscription is dead.

**Attack scenario / failure scenario.**

*Preconditions:* an operator has a webhook subscribed to the identity-backend
alert, configured on a build predating the rename (the alert shipped in the
`2026-08-03` CHAOS-47 work, six days before the rename).

1. The operator exports configuration (`GET /api/config/export`) — or already
   has a backup from that build. `AlertWebhooks` is on the export/import surface
   by design (Finding 10.3).
2. They restore it onto the current build, or onto a rebuilt node, via
   `POST /api/config/import`. The import loop calls `globalAlertStore.Add(wh)`
   with `Events: ["…","idp_unreachable"]`, stored verbatim.
3. The identity backend (LDAP/AD or the OIDC introspection endpoint) goes down.
   Proxy authentication fails closed for the whole gateway — on an in-line SWG
   this is a total egress outage.
4. `noteAuthBackendUnavailable` reaches
   `fireIdentityBackendUnreachableAlert`, whose first statement is
   `if !globalAlertStore.HasSubscriber("identity_backend_unreachable") { return }`.
   No hook matches. **The alert is never delivered, and no delivery-history row
   is written**, so the alert plane also shows nothing to explain the silence.
5. The operator learns about the outage from users, not from the page they
   configured for exactly this.

The same sequence starts at step 2 for any operator automation (Terraform,
Ansible, a provisioning script) still POSTing the pre-rename name.

**Exploitability.** Not attacker-triggered — this is an operator-workflow
regression, and an unauthenticated attacker cannot cause it. But an attacker who
*is* causing the identity-backend outage (see the previous window's SR-…-01/01b,
where a remote client could arm the gate) benefits directly from the resulting
detection blackout.

**Likelihood.** Moderate. Configuration export/import is the documented
backup/restore and node-rebuild path, and the affected build window is short but
live.

**Impact.** Loss of alerting on an availability-critical, fail-closed security
control. No confidentiality or integrity impact; no bypass. Degradation is
silent and indefinite until the operator happens to re-save the webhook from the
UI, which incidentally repairs it.

**Affected assets.** The alert/notification plane
(`internal/alerts.Store`); operator detection of identity-backend outages
(CHAOS-47 / AU-7).

- **CWE:** CWE-778 (Insufficient Logging & Monitoring); secondarily CWE-1188
  (Insecure Default Initialization of Resource) for the un-normalised write path.
- **OWASP:** A09:2021 — Security Logging and Monitoring Failures.
- **Security severity:** MEDIUM (detection integrity, no bypass).
- **Regression risk of the fix:** LOW — see below.

**Fix applied.** Normalisation moved to a single helper applied at **every**
entry point that admits an `Events` list:

```go
func normalizeLegacyEvents(events []string) []string
```

- `Init` now calls it (replacing the inline loop) — behaviour unchanged.
- `Add` calls it before storing, and *before* building the sanitised copy it
  returns, so the API response and the UI checkbox agree with what was stored.
- `Update` calls it before replacing the list.

Two deliberate properties keep the blast radius of the fix at zero for anyone
not affected:

- **A list with nothing to migrate is returned as-is** (nil stays nil, no
  allocation, no reordering). The common path is untouched.
- **De-duplication is scoped to lists the rewrite actually changed.** A rewrite
  can collide with an entry already carrying the current name; that collision is
  resolved. A list an operator deliberately shaped — including one with genuine
  duplicates — is never silently reshaped.

An unknown or attacker-supplied event string is *not* a legacy name and passes
through unchanged; the map is a closed, hard-coded set of two names. The helper
cannot invent a subscription.

---

## Risk Rating

| ID | Title | Severity | Exploitability | Likelihood | Impact | Status |
| --- | --- | --- | --- | --- | --- | --- |
| SR-2026-08-08-01 | Retired alert-event name reintroduced by config import / webhook API | **MEDIUM** | Not attacker-triggered (operator workflow) | Moderate | Silent loss of identity-backend-outage alerting | **Fixed in this change** |

No HIGH or CRITICAL findings in this window.

---

## Regression Analysis

### What was verified, and how

#### 1. LDAP user-bind classification (`auth_ldap.go`) — SOUND

The new `ldapUserBindIsUnreachable` decides whether a failed step-2 bind may arm
the provider-wide cooldown. Getting it wrong in the permissive direction
recreates the previous window's HIGH DoS; getting it wrong in the strict
direction masks a real outage. It was verified against **go-ldap v3.4.14's actual
constants**, not against the comment:

- The client-fault space is exactly `ErrorNetwork` (200) … `ErrorEmptyPassword`
  (206) — the range the code uses. There is no client code above 206 that would
  fall through to "reachable".
- The library only ever *produces* `ErrorNetwork` (×29), `ErrorFilterCompile`
  (×14), `ErrorEmptyPassword` (×3), `ErrorDebugging` (×2),
  `ErrorUnexpectedResponse` and `ErrorFilterDecompile`. Every other `*ldap.Error`
  it returns carries a **server-supplied** result code from the wire.
- The "local" code block (`LDAPResultServerDown` 81 … `LDAPResultClientLoop` 96),
  which would be misclassified as "reachable" if the library used it, appears
  **only** in the description map and is never produced. Not a live gap.
- A non-`*ldap.Error` (context cancellation, raw `net` error) returns
  `true` — unreachable. Unclassifiable faults fail toward the safe side.
- `LDAPResultBusy` (51) / `LDAPResultUnavailable` (52) are carved out as
  unreachable; neither is provokable by one account's state, matching the 429/408
  carve-out on the OIDC leg.

**Fail-closed posture is preserved on every branch.** `Verify` returns `false`
for `err != nil` regardless of classification; the account-rejected error is
**not cached**, so a since-unlocked account authenticates on its very next
attempt.

`ErrorEmptyPassword` (206) is the one code in the client range an *external
caller* can force, and it is raised **without a round trip to the directory** —
so if it could reach `conn.Bind`, `Basic base64("valid.user:")` would be a
remote, unauthenticated primitive for arming the provider-wide cooldown. It
cannot: `Verify` rejects the empty password at `auth_ldap.go:176`, before the
cache, the gate and the dial. Verified by reading the entry point, not assumed.

#### 2. OIDC 4xx now clears the cooldown (`auth_oidc.go`) — SOUND

`errIntrospectClient` is produced only *after* an HTTP status line was received
(`resp.StatusCode != 200` inside `introspect`), so `recordReachable()` on that
branch is genuinely evidence-based: the endpoint answered. RFC 7662 makes the
split clean — an inactive token is `200 + active:false`, so a 4xx is never a
verdict about the caller's token. 429/408 remain carved out as reachability
failures. The change is the symmetric twin of the LDAP fix and closes the
"answered-but-rejected consumes every half-open probe" DoS on this leg.

#### 3. `authProbeGate` — SOUND

Re-verified end to end: `allow()` re-arms on **grant**, not on result, so a probe
that panics or is cancelled cannot leave the gate open against a dead backend;
`recordReachable()` releases every waiter at once; all three methods take the
mutex; the zero value is healthy.

#### 4. `hostutil.StripHostPort` fast path — SOUND (exact equivalence)

This is host **normalisation** on the request path — the shared input to the
threat feed, DPI scanner, scan-exclusion matcher, autoexclude cache and traffic
redactor — so any divergence between the fast path and the body is a
policy-matching bypass primitive, not a performance detail.

The claimed equivalence holds by construction: without a `:` `net.SplitHostPort`
cannot succeed (it locates the port by the last colon), so `host` is never
reassigned; without a leading or trailing bracket `strings.Trim(host, "[]")` is
the identity, because `Trim` only cuts from the ends. `hasHostPortSyntax` is the
exact negation of both conditions, and handles the empty string and the
single-byte case correctly.

Verified rather than argued: `FuzzStripHostPort` differentially compares the fast
path against the pre-fast-path body. **1,929,498 executions, no divergence.**

#### 5. CHAOS-27 alert dedup cap (`dedupSuppressed` / `evictOverCapLocked`) — SOUND

The dedup key embeds `Detail`, which for the request-path producers carries the
attacker-chosen host, so the key space is attacker-controlled — capping it is
correct and matches the existing `topHosts` precedent. The security-relevant
question is the *direction* of failure, and it is right: eviction can only cause
one **extra** delivery of a duplicate, never a suppressed alert. Checked
specifically:

- The just-inserted key is skipped by `keep`, so the alert that triggered the
  eviction is never the one dropped.
- The eviction counter charges **only live keys**, so a monotonic
  `culvert_alert_dedup_evictions_total` cannot be inflated by reclaiming an
  expired entry after a quiet period (the `bf720e5` follow-up).
- The over-cap path is time-rate-limited (`dedupPruneMinInterval`) so a sustained
  flood does not reintroduce the O(len) scan per alert under the process-wide
  mutex — which was itself the CPU half of the original CHAOS-27 defect.

#### 6. CHAOS-27 shared webhook delivery client — SOUND (SSRF guard intact)

Moving from a per-attempt `http.Client` to a process-wide pooled one is the
change most likely to weaken an SSRF control, so it was reviewed directly:

- `ssrf.SafeDialContext` is installed on the shared transport and runs on **every
  dial**. A pooled connection is, by construction, a connection to an address
  that already passed the guard; reuse cannot reach an address that was never
  validated.
- **DNS rebinding is not reachable through the pool.** A name that resolved to a
  public IP at validation time yields a socket to that public IP; rebinding the
  name to `127.0.0.1` afterwards changes what a *new* dial resolves — and that
  new dial is guarded. `IdleConnTimeout: 90s` bounds how long a
  validated-then-rebound host stays reachable at all, matching the pooled clients
  already used for feed and OTLP egress.
- **Behaviour change worth recording:** `ForceAttemptHTTP2: true` is new in
  effect. The previous per-attempt transport set a custom `DialContext` with
  `ForceAttemptHTTP2` false, which disables HTTP/2 in `net/http`; the shared one
  enables it. Go's `http2.Transport` pools client connections by *authority*
  (`scheme://host:port`) and does not implement RFC 7540 §9.1.1 certificate-based
  origin coalescing, so this does **not** create a cross-origin connection-reuse
  primitive. Recorded, not a finding.
- The leak it fixes is real and security-relevant in its own right: every
  delivered alert previously stranded a keep-alive socket in the idle pool of a
  discarded transport (zero-value `IdleConnTimeout` = never expire, no
  finalizer), so a scanning flood against a node with a webhook configured was a
  slow FD leak in the **alert** plane ending in `accept: too many open files` in
  the **proxy** plane — worst exactly while under attack.

#### 7. CodeQL action pin realignment (`.github/workflows/codeql.yml`) — POSITIVE

Closes the previous window's **SR-…-02**: the SAST gate had been failing as a
configuration error ("Loaded a configuration file for version X, but running
version Y") and executing zero queries. `init` is realigned with `analyze`, and
`codeql_action_pin_test.go` now pins all three CodeQL action references equal so
a Dependabot bump landing on one ecosystem and not the others cannot silently
disarm the gate again. Detection coverage restored.

#### 8. `docker-compose.yml` — `CULVERT_CA_PASSPHRASE` forwarded to the `cli` service — ACCEPTED

Reviewed as a secret-scope change. It does not violate the D1.5 operator
contract:

- `${CULVERT_CA_PASSPHRASE:-}` — the compose default is **empty**; no secret is
  baked into a repository file.
- The `cli` service is `profiles: ["cli"]` and invoked as `run --rm`, so it is
  ephemeral and never started by `docker compose up`.
- `cli` already mounts `proxy-data:/data`, which holds the encrypted
  `ca.bundle`. The passphrase is what makes restore validation (dry-run *and*
  commit) possible at all, and restore is `cli`'s job by contract.
- The contract's actual invariant — `/backup` is mounted **only** in `cli`, and
  `cli` does not mount the Docker socket — is unchanged.

Net effect: the container that must decrypt the bundle now can. Recorded under
*Residual Risk* rather than as a finding.

#### 9. Admin-API / metrics surface — NO RBAC DRIFT

`dedup_tracked` and `dedup_evictions_total` were added to the existing
viewer-role `GET /api/alerts/webhooks/history` handler, which retains its
`requireRole(RoleViewer)` and its `uiRoutes` entry
(`ui_routes_meta.go:507`). No new routes, so no C1 forward/reverse parity change.
Both values are integer counters — no endpoint identity, no host, no secret — so
the viewer-role no-sensitive-values guardrail is respected. The matching
`/metrics` lines are counters only. OpenAPI was regenerated in step.

#### 10. `internal/mcpacceptance` (≈1,900 new lines) — NOT PRODUCTION SURFACE

Re-confirmed by import search: nothing outside `internal/mcpacceptance/` and
`cmd/mcp-observe-acceptance/` imports the package, so it is not linked into the
proxy binary. Its file reads are `filepath.Clean`-ed operator-supplied paths with
recorded `#nosec G304` justifications; no `exec.Command`, no
`InsecureSkipVerify`, no unauthenticated network listener. Reviewed as CI
tooling.

### Backward-compatibility regressions affecting security

One, and it is the finding: the alert-event rename is a wire-name change on a
persisted, exportable, API-writable field. The fix makes the migration total
across all three surfaces and proves the migrated name is what reaches disk, so
the compatibility shim converges instead of re-applying forever.

---

## Attack Scenarios

| # | Scenario | Precondition | Outcome before fix | Outcome after fix |
| --- | --- | --- | --- | --- |
| 1 | Operator restores a pre-rename configuration backup, then the directory goes down | Backup taken on a build between the CHAOS-47 alert shipping and the rename | Identity-backend-unreachable alert never delivered; UI shows the box unchecked; no delivery-history row | Subscription migrated on import; alert delivers |
| 2 | Provisioning automation POSTs `idp_unreachable` | Automation written pre-rename | Dead subscription, silently | Migrated on `Add`; alert delivers |
| 3 | Operator PUTs a webhook with the old name | Same | Dead subscription | Migrated on `Update` |
| 4 | Attacker drives an identity-backend outage (prior window's SR-…-01 class) while (1)–(3) hold | Combination | Outage **and** detection blackout | Outage is paged |
| 5 | `Basic base64("valid.user:")` against LDAP proxy auth | Attacker knows one valid username | *Would* arm the provider-wide cooldown via `ErrorEmptyPassword` — **blocked by the empty-password guard, verified** | Unchanged (still blocked) |
| 6 | Webhook host rebinds DNS to a private IP between deliveries | Webhook configured to an attacker-influenced name | Guarded (per-attempt dial) | Guarded (every dial); pooled socket targets the already-validated public IP |
| 7 | Scanning flood produces thousands of unique alert `Detail` values | Node has a webhook configured | Unbounded dedup map + O(len) scan per alert + one leaked FD/2 goroutines per delivery | Capped, amortised, pooled; saturation surfaced as `culvert_alert_dedup_evictions_total` |

---

## Suggested Fix

Applied in this change — normalise retired event names at the **choke point
where data enters the store**, not where the bug was observed:

```go
// internal/alerts/store.go
func normalizeLegacyEvents(events []string) []string  // new

Init:   as.hooks[i].Events = normalizeLegacyEvents(as.hooks[i].Events)
Add:    h.Events           = normalizeLegacyEvents(h.Events)   // before the returned copy
Update: upd.Events         = normalizeLegacyEvents(upd.Events)
```

Deliberately **not** done, and why:

- **No event-name allowlist on the API.** Rejecting unknown event names would be
  the stricter validation and is tempting, but it is a breaking change to a
  surface with no versioning: a node running an older admin UI, or automation
  subscribing to an event added in a newer build, would start receiving 400s.
  Normalising a closed set of retired names is the non-breaking half of the same
  goal. Recorded as a candidate for a separate, deliberate change.
- **No forced resave on load.** `Init` migrates in memory and lets the next
  legitimate mutation persist, matching the legacy-cleartext-secret migration
  immediately below it. Writing to disk during startup load is a wider change
  than the defect justifies.
- **No change to the LDAP/OIDC gating logic.** It was reviewed and found correct;
  the security-behaviour rule is not to change what is not broken.

---

## Files

**Changed by this review:**

- `internal/alerts/store.go` — `normalizeLegacyEvents` helper; applied in `Init`
  (replacing the inline loop), `Add`, and `Update`.
- `internal/alerts/store_legacy_events_test.go` — new; 7 tests (below).

**Reviewed, unchanged:**

`auth_ldap.go`, `auth_oidc.go`, `auth_backend_health.go`,
`internal/hostutil/hostutil.go`, `internal/alerts/store.go` (dedup + delivery
client), `events.go`, `ui_security.go`, `diagnostics.go`, `static/index.html`,
`docker-compose.yml`, `.github/workflows/codeql.yml`, `api/openapi/*`,
`internal/mcpacceptance/*`.

---

## Required Tests

All seven are in `internal/alerts/store_legacy_events_test.go` and were confirmed
to **fail against the pre-fix code and pass after** (the three discriminating
tests were re-run with the fix disabled — see below).

| Test | Class | Pins |
| --- | --- | --- |
| `TestStore_Add_MigratesLegacyEventNames` | **Positive / regression** | Config-import and API-create path: the retired name is subscribed to the current event, and the **returned** copy carries the migrated list so the UI checkbox matches what is stored |
| `TestStore_Update_MigratesLegacyEventNames` | **Positive / regression** | `PUT /api/alerts/webhooks`, which replaces the whole list |
| `TestStore_Add_LegacyMigrationDedupes` | **Boundary** | A list carrying both the retired *and* the current name does not end up with the current name twice; order preserved |
| `TestStore_Add_LeavesCurrentEventListUntouched` | **Negative** | A list with nothing to migrate is stored verbatim — including genuine duplicates and `"*"` — so the de-dup never silently reshapes an operator's list |
| `TestNormalizeLegacyEvents_Boundaries` | **Malformed input** | `nil` stays `nil`; empty stays empty; the empty string and an unknown/attacker-supplied name pass through and are never mapped onto a real event |
| `TestStore_LegacyMigration_ConcurrentAddDispatch` | **Concurrency** | 16 concurrent `Add` against concurrent `HasSubscriber`/`List` under `-race`; no reader observes a half-rewritten list, no subscription lost |
| `TestStore_LegacyMigration_SurvivesPersistRoundTrip` | **Regression (durability)** | Asserts on the **persisted bytes**, not a reloaded store — `Init` re-migrates on load, so only the file distinguishes "migrated on the way in" from "re-migrated every restart forever" |

Existing `TestStore_Init_MigratesLegacyEventNames` (load path) still passes
against the refactored `Init`.

**Verification performed for this review:**

- `go build ./...` — clean.
- `go vet ./internal/alerts/ ./internal/hostutil/ .` — clean.
- `go test -race ./internal/alerts/` — pass.
- Fix disabled at `Add`/`Update` → `TestStore_Add_MigratesLegacyEventNames`,
  `TestStore_Update_MigratesLegacyEventNames`,
  `TestStore_Add_LegacyMigrationDedupes` and
  `TestStore_LegacyMigration_SurvivesPersistRoundTrip` all fail. The tests
  discriminate; they are regression tests, not tautologies.
- `go test -fuzz=FuzzStripHostPort -fuzztime=20s ./internal/hostutil/` —
  1,929,498 executions, no divergence from the pre-fast-path body.
- `go test ./...` — full suite pass.
- Authorization/authentication coverage: the existing
  `auth_ldap_gate_test.go`, `auth_oidc_test.go`, `auth_backend_health_test.go`,
  C1/C1.5/C2 route-parity and D0 baseline suites were run and pass; the change
  adds no route and alters no role.

---

## Residual Risk

1. **The LDAP empty-password guard is load-bearing at a distance.**
   `ldapUserBindIsUnreachable` classifies `ErrorEmptyPassword` (206) as
   *unreachable*, which is correct for a genuine client fault but would be a
   remote, unauthenticated cooldown-arming primitive if an empty password ever
   reached `conn.Bind`. Today it cannot, because `Verify` rejects it three
   screens earlier — but nothing at the classifier says so, and a future caller
   of `verify()` that skips `Verify` would reintroduce the previous window's HIGH
   finding for the third time. **Recommended (separate change):** assert the
   invariant where it is relied upon rather than where it happens to hold — a
   comment at `ldapClientErrorCeil` naming the guard, and a test that calls
   `Verify("user", "")` and asserts the gate did not arm.
2. **An always-4xx introspection endpoint now reports healthy.** With the
   OIDC 4xx branch calling `recordReachable`, an IdP whose client credentials
   have expired (401 on every introspection) fails all proxy authentication
   closed while the `identity_backend` operator-contract row and the degraded
   gauge stay green. This is the deliberate blast-radius-over-detection trade the
   CHAOS-47 design made, and the pre-window behaviour was equally silent for a
   never-degraded backend — but the *authentication-failure* rate is the only
   signal that distinguishes it, and nothing correlates the two today. Candidate
   for CHAOS-49.
3. **Server-wide LDAP rejections are classified "reachable".** Codes such as
   `strongerAuthRequired` (8) or `confidentialityRequired` (13) are server-wide
   configuration faults that deny every user, yet the directory *did* answer, so
   they clear rather than arm. Fail-closed is preserved (every user is denied);
   the residual is detection, same shape as (2).
4. **No event-name allowlist on the webhook API.** Any string is accepted and
   stored, so a typo'd event name is an inert subscription that looks configured.
   The migration closes the two names we know about; it cannot close typos. See
   *Suggested Fix* for why an allowlist was not added here.
5. **`CULVERT_CA_PASSPHRASE` now reaches a second container.** The ephemeral
   `cli` service can decrypt the CA bundle it already had access to. Operators
   should keep the compose `.env` at `0600` and prefer passing the value per
   invocation on hosts where other users can read the project directory.
6. **`ForceAttemptHTTP2` on the alert delivery client.** Reviewed and found not
   to create a cross-origin reuse primitive under Go's current `http2.Transport`
   (authority-keyed pooling, no certificate coalescing). This is a property of
   the standard library, not of Culvert's code, so it is worth re-checking if the
   delivery client ever gains a custom `TLSClientConfig` or an explicit
   `http2.Transport`.
7. **Log-volume amplification on the LDAP account-rejected path.** A client
   looping binds against one locked account now produces two unrate-limited log
   lines per attempt (up from one). The process log is async and bounded
   (`internal/logsink`), so this costs disk and noise rather than latency, and
   proxy-auth attempts are already logged per request. Recorded, not fixed.
