# Security Regression Review — unauthenticated `/ready` DP-row disclosure, MCP PR-12 CP/DP transaction, at-rest install fallback (window `bc67b7b` → `b697cf3`)

> **Reviewer role:** Security Regression Engineer (AppSec / Secure Code Review / Product Security)
> **Review date:** 2026-08-14
> **Baseline:** `bc67b7b` — head of the previous review's window
> (`docs/security-reviews/2026-08-12-chaos28-root-ca-failclosed-readiness-detail-window.md`)
> **Head:** `b697cf3` (`main`)
> **Scope reviewed:** every code-bearing change in the window — PRs #1117, #1118,
> #1120, #1122, #1125, #1126 — plus an adversarial re-review of the surface the
> previous window's fix touched.
>
> **Method.** Prioritised by *live blast radius*, and deliberately weighted
> toward **completeness of the previous window's fix**. A remediation that
> closes a class on the rows it happened to test, while leaving sibling rows on
> the same surface untouched, is the highest-yield place to look for a surviving
> instance — the reviewers have already moved on, and the guardrail's existence
> reads as coverage.
>
> 1. **Unauthenticated network surfaces** — `/ready` on the **proxy listener**,
>    which every client on the network already dials. The previous window fixed
>    two of its rows and left a standing sweep test behind; the first question
>    asked here was whether that sweep actually covers every row the process can
>    emit.
> 2. **The MCP CP→DP signed-distribution transaction (PR-12, #1126)** — the
>    largest change in the window (+2,088 lines). It introduces the first
>    production caller that composes a DP applier from **env-provisioned crypto
>    trust**, and couples two durable stores into one transaction. Reviewed for
>    trust-store parsing, fail-closed composition, signature-before-trust
>    ordering, and split-state on crash.
> 3. **Acceptance PKI lifetime (#1125)** and the **at-rest encryption installer
>    fallback (#1117/#1118)** — both touch key material.

---

## Executive Summary

**One finding, fixed in this change:**

- **SR-2026-08-14-01 (MEDIUM, information disclosure / security-posture
  oracle)** — the **unauthenticated** `/ready` probe on the **proxy listener**
  answered its two data-plane rows (`cp_poll`, `node_cert`) with `fmt.Sprintf`
  over live internals. Together they published the control plane's internal
  address and port, the raw gRPC/TLS transport error, the exact remaining
  lifetime of the node's mTLS identity, and — the part that actually arms an
  attacker — an explicit, machine-readable statement of the **enforcement
  posture**: `serving last-known-good config; policy/auth updates are not
  arriving`. This is the *same class* the previous window closed on the `ca` and
  `clamav` rows two days earlier, on the same endpoint, surviving because the
  guardrail left behind could not see these rows.

**Why the existing guardrail missed it.** The previous window's sweep,
`TestReadyz_NoDetailCarriesRawInternals`, iterates *the rows present in the test
process* — explicitly so that "a row added later cannot quietly reintroduce the
class". But `appendDPHealthChecks` returns early unless `audit.DPMode()` is set,
and no disclosure test set it. The DP rows were never in the swept set. The
sweep was therefore structurally incapable of covering the two rows that leaked
the most, and its presence made the surface look walled.

**The rest of the window is clear.** PR-12's transaction ordering, fail-closed
trust parsing and compensating abort were reviewed adversarially and hold; the
installer's at-rest fallback and the acceptance-PKI lifetime guard are both net
security improvements. Details in *Regression Analysis* below.

---

## Security Findings

### SR-2026-08-14-01 — the unauthenticated readiness probe published the control plane's address, the raw renewal error, the node cert's remaining lifetime, and an explicit "policy/auth updates are not arriving" signal

| | |
|---|---|
| **Severity** | **MEDIUM** (information disclosure enabling attack timing; no direct bypass) |
| **CWE** | CWE-209 (Generation of Error Message Containing Sensitive Information); CWE-497 (Exposure of System Data to an Unauthorized Control Sphere); CWE-200 |
| **OWASP** | A01:2021 Broken Access Control (unauthenticated read of operator-only state); A05:2021 Security Misconfiguration |
| **Regression risk** | **High class-recurrence** — third instance of the same class on the same endpoint (`state_file_*` fixed earlier, `ca`/`clamav` fixed 2026-08-12, DP rows here) |
| **Affected assets** | Control-plane network location; DP node mTLS identity lifetime; the fleet's policy-freshness state |

#### What the code did

`/ready` is dispatched by `routeProxyListenerBuiltin` (`pac.go`) on the **proxy
listener** (`main.go:908`) — no authentication, no IP guard, no role. Any client
that can use the gateway can read every byte of the response.

`appendDPHealthChecks` (`readyz_dp_health.go`) built both of its rows with
`fmt.Sprintf` over live internal state:

```go
cp.Detail = fmt.Sprintf(
    "control plane unreachable for %s — serving last-known-good config; policy/auth updates are not arriving",
    time.Since(time.Unix(0, since)).Round(time.Second))
...
cert.Detail = fmt.Sprintf(
    "node certificate EXPIRED %d day(s) ago and renewal is failing (last error: %s)", -days, lastErr)
```

`lastErr` is `renewErr.Error()` recorded by `alertDPCertRenewalFailure`
(`dp_enrollment.go:439`) straight from the renewal loop — i.e. the raw
gRPC/transport error from `renewDPCert`'s `RenewCert RPC: %w`.

#### Proof (observed, not inferred)

Driving the **real** handler through the **real** producers
(`alertDPCertRenewalFailure`, `dpMarkCPPollFailing`), against `main` at
`b697cf3`:

```
cp_poll   → "control plane unreachable for 10m0s — serving last-known-good config;
             policy/auth updates are not arriving"

node_cert → "node certificate expires in 3 day(s) and renewal is failing
             (last error: RenewCert RPC: rpc error: code = Unavailable desc =
             connection error: desc = \"transport: Error while dialing dial tcp
             10.0.3.7:9443: connect: connection refused\")"
```

Reproduced by the four tests added in this change, every one of which failed
before the fix and passes after.

#### Attack scenario

1. An insider, a compromised endpoint, or malware on any host permitted to use
   the gateway polls `http://<proxy-host>:<proxy-port>/ready` on a timer. No
   credentials are needed — this is the same port and the same reachability the
   client already has in order to browse.
2. **Reconnaissance.** `node_cert`'s detail carries the control plane's internal
   address and port (`10.0.3.7:9443`) — a host the attacker has no other route
   to discover from the client network — and the transport-level reason it is
   unreachable, which distinguishes "firewalled" from "process down" from "TLS
   rejected". That is lateral-movement targeting handed over for free.
3. **Timing.** `cp_poll`'s detail states, in machine-readable form, that this
   node is serving last-known-good config and that **policy and auth updates are
   not arriving** — and, via the elapsed duration, exactly how stale it is. The
   security consequence is concrete: a credential revoked at the control plane,
   a destination newly added to a block rule, or a tightened decryption profile
   has *not* reached this node and will not until the row clears. The attacker
   learns the precise window in which the old, laxer permit set is still in
   force.
4. **Expiry countdown.** `node_cert`'s days-left is a countdown to the moment
   this node's mTLS identity dies and it stops receiving policy permanently
   (`DP certificate expired at … — re-enroll to get a new cert`). An attacker
   who wants a node frozen on stale policy learns exactly when that happens
   without touching anything, and — combined with step 2 — knows where to aim a
   short, cheap disruption of the CP to *cause* it.

Each row alone is a leak; together they are a targeting package plus a schedule.

#### Preconditions, exploitability, likelihood

- **Preconditions:** node runs as a cluster **data plane** (`audit.DPMode()`),
  and the corresponding subsystem is degraded — a CP outage past the 5-minute
  grace, or a renewal failure inside the 30-day window. Both are ordinary
  operational states, not exotic ones; the CP-poll row in particular fires on
  every CP maintenance window that runs long.
- **Exploitability:** trivial. One unauthenticated HTTP GET, no parsing beyond
  reading a JSON string. Nothing distinguishes the attacker's poll from a load
  balancer's — there is no rate limit or auth event to alert on.
- **Likelihood:** moderate-to-high in a clustered deployment. The information is
  most available precisely when the fleet is degraded, i.e. when an attacker
  most benefits and defenders are most distracted.
- **Impact:** no direct bypass. The value is entirely in reconnaissance and
  timing — which is the same value the previous window judged MEDIUM for the
  `ca`/`clamav` rows, on strictly less material.

#### Why this is in scope for a regression review

The rule was already written and already applied — twice, on the same function
family, in the two days before this window's head:

- `appendStateFileChecks`: *"/ready is served UNAUTHENTICATED on the proxy port
  … so the row carries only a FIXED, non-path detail."*
- `appendCAReadinessCheck` (commit `cb1e126`, then `b0714e3`): *"EVERY detail on
  this row is a FIXED string … The detail also does not state the ENFORCEMENT
  POSTURE, which is the part that actually arms an attacker."*

`appendDPHealthChecks` sits in the same `computeReadiness` call, three lines
below the ClamAV row that was redacted, and published strictly more of the same
class. The remediation was applied per-row rather than per-surface, and the
guardrail meant to generalise it (`TestReadyz_NoDetailCarriesRawInternals`)
could not reach the unfixed rows because they only exist in DP mode. Worse, the
DP suite **actively pinned the vulnerable behaviour**:

```go
if !strings.Contains(row.Detail, "connection refused") || !strings.Contains(row.Detail, "day") {
    t.Errorf("node_cert detail should carry days-left and the last error, got %q", row.Detail)
}
```

— the same shape as `TestHandleReady_SurfacesCALoadFailure` before `cb1e126`
retargeted it. A test asserting the leak is the strongest possible signal that
the class is unclosed, not that the behaviour is intended.

#### Fix applied

**1. Both details are now fixed, operator-directed strings.**

```go
cp.Detail   = "control plane connectivity is degraded — see server logs"
cert.Detail = "node certificate renewal is failing — see server logs"
```

- `cp_poll`'s detail is now **identical on both branches**. Only the *status*
  distinguishes a sustained outage from one inside the grace window, so the
  detail carries no measurement an observer can use to size the stale-config
  window.
- `node_cert` no longer distinguishes expired from expiring. That distinction is
  itself the disclosure — how far past `NotAfter` this node's identity is.

**2. The raw cause never enters the probe-facing state at all** (defence in
depth). `dpNodeCertRenewal` is reduced to the single boolean the row needs:

```go
var dpNodeCertRenewal struct {
    mu      sync.Mutex
    failing bool
}
```

`recordDPCertRenewalFailure(days int, renewErr error)` becomes
`recordDPCertRenewalFailure()`, and `dpCertRenewalFailureSnapshot()` becomes
`dpCertRenewalFailing() bool`. The struct's *only* consumer is the
unauthenticated row, so anything retained there is one `fmt.Sprintf` away from
the public surface — which is exactly how both values came to be published.
Making the leak unreachable by construction is stronger than leaving it
unwritten by the current formatter.

**3. Pointing "see server logs" was verified, not assumed.** Both causes are
already logged on every occurrence, by their own loops:

- `controlplane_client.go:247,264` — `DataPlane: GetConfig error: %v` (and the
  post-failover variant) on every failing poll.
- `dp_enrollment.go:338,363` — `DataPlane: cert renewal check: %v` /
  `DataPlane: CA rotation renewal failed: %v` on every failed attempt, plus the
  latched `cert_expiry` alert.

This matters because the previous window found the opposite for ClamAV — whose
runtime failure is *not* logged — and correctly pointed that row at the admin UI
instead. The check was redone here rather than copied.

**4. The CP-reachability posture is not lost to operators.** It is already
stated in full, with an operator action, on the **role-gated**
`/api/diagnostics` `dp_last_known_good_config` contract row
(`diagnostics.go:217-227`): *"control plane unreachable; serving last-known-good
local config … new policy/auth changes will not arrive until CP polling
recovers."* Nothing new needed to be published to preserve operator visibility.

**Deliberately NOT done:** the raw renewal cause was **not** relocated to the
`/api/diagnostics` contract rows. Those rows are **viewer**-role, and the
established `identity_backend` contract (CHAOS-47, `CLAUDE.md`) is explicit that
a viewer-role contract row carries the backend name and counts, *never* the
cause. Adding it there would have traded one over-disclosure for a smaller one.

#### Files

- `readyz_dp_health.go` — fixed details; probe state reduced to a boolean; the
  disclosure contract recorded at the top of the file alongside the existing
  CHAOS-09 rationale.
- `dp_enrollment.go` — call site updated; comment records why the cause must not
  reach the recorder.
- `readyz_dp_health_test.go` — the two assertions that pinned the leak retargeted
  onto the redaction contract (subsystem named, log pointed at), matching what
  `cb1e126` did to `TestHandleReady_SurfacesCALoadFailure`.
- `readyz_dp_detail_disclosure_test.go` — **new**.

#### Required tests — all added and passing

| Test | Class | What it pins |
|---|---|---|
| `TestReadyz_CPPollDetailWithholdsPostureAndElapsed` | Regression (negative) | Row survives and still fails; detail carries no `last-known-good` / `policy` / `auth` / `not arriving` / elapsed duration; points at the log |
| `TestReadyz_NodeCertDetailWithholdsCauseAndLifetime` | Regression (negative) | No CP address, port, `dial tcp`, `rpc error`, `connection refused`, days-left or expired/expiring distinction |
| `TestReadyz_DPRowsRawErrorNeverEntersProbeState` | Boundary / defence-in-depth | The probe state retains only the boolean and the mutex — reflected over the struct, so a re-added string or int field fails the build's contract, not just the formatter |
| `TestReadyz_DPSweepNoDetailCarriesRawInternals` | **Coverage-gap closure** | The standing sweep re-run with DP mode ON and both rows populated — asserts the rows are actually present before sweeping, so the gap cannot silently reopen |
| `TestReadyz_DPRowVerdictsUnchanged` | Positive / monitoring-regression guard | Default verdict stays `200/ready` (report-only) and `?strict=1` stays `503/not_ready` with both rows failing — the redaction changed only the strings |
| `TestHandleReady_*` (existing CHAOS-09 suite) | Regression | Grace window, recovery, out-of-window renewal failure, strict gating — all unchanged and green |

Malformed-input and concurrency coverage: the probe state is exercised through
the real producers under `-race -count=2`, and the full root package passes
under `-count=1 -shuffle=on` (the audit-ring/global-state pollution class).

#### Residual risk

- **Row existence is still a signal.** `cp_poll: fail` tells an unauthenticated
  observer that *a* named subsystem is degraded. That is the deliberate,
  documented trade: CHAOS-06/09 exist so a degraded node is visible to probes,
  and a load balancer needs the status to act. What is withheld is the
  *consequence* and the *measurement*, which is where the attacker value sits.
  Operators who consider even row presence too revealing already have the lever:
  probe the authenticated `/api/diagnostics` instead.
- **`saas_feed` publishes `snap.State.String()`.** Reviewed and accepted: it is
  a bounded enum with no path, address, cause or posture text. Noted so a future
  widening of that enum is a conscious decision.
- The DP rows remain report-only by default. Unchanged by this work, and
  the reasoning (a CP outage must not eject the whole DP fleet from a
  default-configured load balancer) is unaffected by the string change.

---

## Regression Analysis — cleared changes

### MCP CP→DP production composition + rollout transaction (PR-12, #1126)

The largest change in the window. Reviewed adversarially; **no finding**. Four
properties were specifically checked:

1. **Trust parsing fails closed.** `resolveMCPDistributionStartupConfig` is a
   pure resolver: unset or `[]` ⇒ `not_configured` (no applier, DP apply path a
   no-op, `ConfigSnapshot` byte-identical to pre-PR-10). Every malformed input —
   bad JSON, wrong `alg`, non-base64 key, wrong key length, rejected trust store
   — returns a *disabled* config with a bounded reason. There is no path that
   yields `Enabled: true` with a nil or empty `Trust`. Key length is checked
   against `ed25519.PublicKeySize` explicitly, so a short/long key cannot reach
   the verifier.
2. **Signature is verified before any payload is trusted.** The coordinator's
   step-1 pre-check reads `env.Payload` while still unverified — but it can only
   *reject*, never admit: an executing mode without execution dependencies, or a
   capability-mismatched rollout, is refused before any state is staged. The
   config actually committed in step 3 is the same in-memory object whose
   content hash and signature `Applier.Apply` verified in step 2. No
   unsigned-local-shortcut path exists.
3. **Composition is all-or-nothing.** Both appliers are constructed and
   `Recover`ed off to the side; a failure in either registers *neither*, so a
   corrupt durable state cannot leave a half-composed DP with one capability
   trusting and one not. `enabled` is flipped last.
4. **The compensating abort is ordered persist-before-swap** and never moves the
   trusted epoch backwards. `AbortApplied` with no previous snapshot (the
   first-apply case) was specifically checked: `ActiveStore.Restore(nil, nil)` is
   valid — the guard only rejects `previous != nil && current == nil` — so the
   fresh-DP path compensates correctly rather than erroring into the
   double-fault branch.

Execution stays fail-closed independently: `execDepsConfigured` returns false for
both capabilities in the shipped build, `markGatewayExecDepsReady` /
`markManagementExecDepsReady` have no production caller, and `restore()` clamps a
hand-crafted executing state file back to Disabled.

### MCP acceptance PKI lifetime guard (#1125)

Rejects stale qualification PKI before acceptance. Narrowing change, fail-closed
direction, no new surface. Cleared.

### At-rest encryption installer fallback (#1117 / `c86e44c`, `4940c6e`)

A net improvement: the old early-return treated *either* passphrase being set as
"already configured", so an IaC install that pre-exported only
`CULVERT_LOG_PASSPHRASE` silently generated an **unencrypted** SSL-inspection
Root CA private key. The split guard fixes that. The follow-up correctly applies
the same character allowlist used by the interactive path before persisting a
reused value, since docker compose re-interpolates `$`-references when reading
`.env` — writing an unvalidated value could persist a *different* string than
the one in use, silently splitting one intended key into two. Both directions
verified; cleared.

### `/ready` `ca` + `clamav` redaction (`cb1e126`, `b0714e3`)

Re-reviewed as the immediate predecessor. The fix itself is correct and complete
*for the rows it covers*: details are fixed strings, the `ca` row stays
report-only, the `clamav` row still gates to 503, and the ClamAV row correctly
points at the admin UI rather than the log because the runtime cause is not
logged. The defect is one of **scope**, not correctness — see
SR-2026-08-14-01.

### IdP-registry hardening (CHAOS-49, `1886594`, `2d5b757`)

Carried over from the previous window's head; re-read for the introspection-401
change. Treating a 401 as a provider-wide fault rather than a caller error is
correct: RFC 7662 makes an inactive token a `200` + `active:false`, so any
non-200 is an endpoint/credential fault of *our* client, not a verdict about the
presented token. Caching it as a denial would have denied valid credentials for
a full TTL. Cleared.

---

## Risk Rating

| Finding | Severity | Exploitability | Likelihood | Impact | Status |
|---|---|---|---|---|---|
| SR-2026-08-14-01 — unauthenticated `/ready` DP-row disclosure | **MEDIUM** | Trivial (one unauthenticated GET) | Moderate–High in clustered deployments | Recon + attack timing; no direct bypass | **Fixed in this change** |

No HIGH or CRITICAL findings in this window.

---

## Residual Risk (window-level)

- **The class is now walled on this surface, but the wall is test-shaped.** The
  sweep covers every row *the test process can produce*, which is now the full
  set including DP mode. A future row gated behind some *third* condition no
  disclosure test sets would repeat this exact failure. The structural fix would
  be a type-level constraint on `readinessCheck.Detail` (a closed set of
  approved strings) rather than a sweep; that is recorded here as a deliberate
  deferral, not an oversight — the sweep plus the assert-rows-are-present guard
  raises the cost of the mistake substantially at a fraction of the churn.
- **MCP distribution remains disabled by default** and no production path
  provisions `CULVERT_MCP_DISTRIBUTION_TRUST_KEYS`. The PR-12 review above is of
  a path that is correct *and currently unreachable in a default deployment*;
  it should be re-reviewed when a real trust store is first provisioned, since
  that is when the durable-state and crash-window reasoning becomes live.

---

## Verification performed

```
go build ./...                                    # clean
go vet ./...                                      # clean
gofmt -l <changed files>                          # clean
go test -count=1 -timeout=20m .                   # ok  121.083s
go test -count=1 -shuffle=on -timeout=25m .       # ok  119.706s
go test -race -count=2 -run 'TestReadyz_|TestHandleReady_|TestDPCert|Renewal' .   # ok
```

The four new disclosure tests were confirmed **failing against `b697cf3`
(pre-fix)** with the verbatim leaked strings quoted in *Proof* above, and
passing after.
