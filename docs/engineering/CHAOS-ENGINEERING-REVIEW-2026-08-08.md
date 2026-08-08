# Chaos Engineering Review — 2026-08-08

**Domain:** the SSL-inspection Root CA across its expiry boundary
**Register items:** CHAOS-30 (closes CA-1, CA-1b, CA-1c, CA-5; partly CA-4; raises CA-16)
**Verdict:** four confirmed defects — one of them a fail-open in the MITM trust
core and one a latent process-killing nil-deref — all fixed, with regression
gates proven to fail against the pre-fix code.

> **On the ID.** This run does not mint a new number. **CHAOS-30** was registered on
> 2026-07-07 as *"No proactive CA-expiry alert (`internal/alerts/store.go:17` documents
> a startup alert that does not exist); rotation failures unalerted; `signLeaf` keeps
> minting leaves under an expired root"* — which is verbatim FS-1 and FS-4 below. It has
> been OPEN in every status table since. CHAOS-28 and CHAOS-29 are already taken by
> unrelated findings (rotation-triggered renewal retry; `CULVERT_SESSION_SECRET`
> handling), and the register already carries one ID collision it wants renumbered, so
> claiming the pre-registered ID is the correct move rather than adding a second.

---

## Executive Summary

Culvert already treats *one* certificate lifecycle as a chaos surface. CHAOS-12 and
CHAOS-09 gave the DP↔CP **node** certificate a latched escalation alert, a `/ready`
row, and an operator-contract verdict, on the reasoning that a node whose renewal
keeps failing "slides toward an expiry brick." That reasoning is right, and it was
never applied to the certificate with the larger blast radius.

The **SSL-inspection Root CA** signs a leaf for every inspected HTTPS session on the
node. Its expiry does not degrade one node's control-plane link — it stops inspected
HTTPS working for every client behind the gateway, simultaneously. This pass asked
what Culvert does at and around that boundary. The answer was: it keeps signing, and
it does not notice.

| # | Failure mode | Class | What made it survive prior review |
|---|---|---|---|
| 1 | `signLeaf` mints leaves from an **expired** Root CA — fail-open, silent | Silent fail-open in the trust core | auto-rotation is assumed to make expiry unreachable |
| 2 | Leaf `NotAfter` is unconditionally `now+24h` and can **outlive its issuer** | Correctness | the 30-day rotation window "guarantees" ≥30d of CA life |
| 3 | Rotation loop's first tick is at **+24h** — a full day of blind spot after every boot | Unexpected startup order | the loop is a steady-state design; boot state was not considered |
| 4 | No early-warning or expired alert for the Root CA; `/health`, `/ready` and the operator contract all report it healthy | Silent failure / observability | `cert_expiry` exists, so the event looked covered |

The unifying error is the same one the standing register names as Culvert's dominant
theme — **a security control degrading silently** — with a twist specific to this
subsystem: every surface that *could* have reported the condition was keyed on
"is a CA loaded?" (`certMgr.Ready()`), which stays `true` forever after the CA dies.

A fifth finding is recorded but **not fixed** here, because the fix is a design
decision rather than a defect repair: dual-CA overlap does not do what its name
implies (§6).

---

## Failure Scenarios

### FS-1 — An expired Root CA keeps signing (fail-open, silent)

**Current behavior (pre-fix).** `signLeaf` (`internal/ca/ca.go`) read `caCert`/`caKey`
under the lock and went straight to `x509.CreateCertificate`. There was no
`time.Now().After(caCert.NotAfter)` check anywhere on the path — not in `signLeaf`,
not in `GetCert`, not at the `handleTunnelInspect` gate, which tests only
`certMgr.Ready()` (i.e. `caCert != nil`).

So past `NotAfter` the proxy produced a structurally perfect certificate, signed by a
dead issuer, and completed its half of the MITM handshake. Every client then rejected
the chain on the **issuer's** dates.

**Expected behavior.** A certificate that cannot validate is not a certificate. The
engine refuses to issue it, and the refusal is an event the proxy can count, log and
alert on.

**Failure mode.** Fleet-wide inspected-HTTPS outage whose only symptom lived on the
*client* side. The gateway's own logs, metrics, health probes and operator contract
all reported a healthy CA throughout. `GetCert`'s cache made it stickier: a leaf
signed seconds before expiry was served from cache for up to `certCacheTTL` (1h)
afterwards.

**Why "recovery" was worse than it looked.** `RotateIfNeeded` *does* fire on an
expired CA — `time.Until(expiry)` is negative, which is `< caRotationOverlap` — so it
looks self-healing. It is not: rotation generates a **new self-signed root that no
endpoint trusts**. The node comes back with a CA that is not expired and still cannot
inspect anything. Recovery here is inherently an operator action (distribute the new
root), which is exactly why the operator has to be told, promptly and unambiguously.

**How it is reachable despite auto-rotation.** Rotation is a 24h loop inside one
process. Anything that stops the process from ticking for long enough gets you here:
an appliance restored from an old backup or image, a node powered off across a long
maintenance window, a clock jump forward, a rotation that keeps failing to persist
(register row CA-2 — `SaveCA` failure is logged and swallowed, so the new CA lives
only in RAM and the *old, near-expiry* bundle reloads on the next restart), or an
operator-imported enterprise CA that expires while `SaveCA`/rotation is misconfigured.

**Fix.** `signLeaf` returns `ErrCAExpired` past `NotAfter`, increments
`signFailures`, and issues nothing. `GetCert` propagates the error, so the handshake
fails at the proxy — with a server-side error object — instead of completing with an
unusable certificate. The leaf cache is untouched by a refusal.

**Posture note.** This is deliberately fail-**closed**, not a fallback to SSL-bypass.
Bypassing would keep traffic flowing at the cost of silently disabling DPI, CDR and
file-blocking for the inspected set — which is precisely the degradation register row
CA-3 already classifies as a gap. Availability is not improved by the alternative
anyway: the client rejects the chain either way. What changes is that the proxy now
knows.

### FS-2 — A leaf can outlive its issuer

**Current behavior (pre-fix).**

```go
NotBefore: time.Now().Add(-5 * time.Minute),
NotAfter:  time.Now().Add(24 * time.Hour),
```

Unconditional. In the CA's final 24 hours every leaf claimed validity past its own
issuer's `NotAfter`.

**Why the 30-day rotation window does not cover it.** It covers the *steady state*
only. It does not cover FS-3's boot blind spot, a rotation that failed to persist, or
the dual-CA secondary. And `GetCert`'s cache-freshness test is on the **leaf's**
`NotAfter` — so an over-long leaf is exactly the kind of entry the cache will keep
serving after the CA behind it has died.

**Fix.** `notAfter` is clamped to `caCert.NotAfter`. Leaf expiry becomes an honest
signal, and — together with FS-1 — the window in which a cached leaf can outlast the
trust backing it is bounded to zero. All three `time.Now()` calls in `signLeaf` were
also collapsed to one `now`, so a clock change mid-function can no longer produce
`NotBefore > NotAfter`.

### FS-3 — 24-hour rotation blind spot after every boot

**Current behavior (pre-fix).** `StartCAAutoRotation` created a `time.Ticker` and
entered `select` immediately. `Ticker` does not fire at t=0, so the first rotation
check happened a full `RotationCheckInterval` (24h) after start.

**Failure mode.** A node that boots with a CA already inside the rotation window
spends its first day neither rotating nor reporting. The blind spot is widest exactly
when the CA is in the worst shape: a node whose CA is already expired reboots into a
total inspected-HTTPS outage and learns nothing about it for 24 hours.

**Fix.** The round is extracted as `caRotationRound` and run once before entering the
loop. Both CAs are still guarded separately per CHAOS-24 (contain the round, never
let the goroutine exit), and the new expiry check gets its own guard so a fault in the
alerting path cannot suppress rotation itself.

### FS-4 — Nothing reported the condition

Five surfaces could have carried this signal. Pre-fix, all five reported healthy:

| Surface | Pre-fix behavior |
|---|---|
| `cert_expiry` alert | only producer was `RotationObserver` — fires **after** a rotation succeeds. There was no producer for rotation *not* happening, which is the case that matters. (Register row CA-5: the alert-store contract already claimed "fired on startup if ≤30 days".) |
| `/health` | `ssl_inspection: "ready"` (keyed on `Ready()`); `ca_expires_days` returns **−1 both for "no CA" and for "expired yesterday"** — the two states demanding opposite responses |
| `/ready` | `ca` row `"ok"` |
| `/api/diagnostics` | `root_ca` → `diagOK`, *"root CA initialised"* |
| `/metrics` | no CA expiry series at all |

**Fix.** A latched escalation alert modelled directly on CHAOS-12 (`ca_expiry.go`):
levels ≤30d / ≤7d / expired, one alert per escalation rather than one per 24h tick,
latch cleared when the CA returns to healthy so the next real escalation is not
swallowed, restart re-fires once at the current level (documented, same posture as the
DP-cert and release-catalog latches). It runs at startup via `deferStartupAlert` and
after every rotation attempt.

Evaluation order is load-bearing: rotation is attempted **first**, expiry evaluated
**after**. On a healthy appliance auto-rotation resolves the condition before it can
alert, so a fired alert means what an operator needs it to mean — *rotation did not
fix this.*

The other four surfaces were corrected to match:
`/health` gains `ca_expired` and reports `ssl_inspection: "expired"`; `/ready`'s `ca`
row fails (still **report-only** — an expired inspection CA must not eject an
otherwise-serving forward proxy from every load balancer at once; probes that want
that opt in via `/ready?strict=1`); `checkRootCA` returns `diagFail`/`diagWarn` with
an operator action; `/metrics` gains `culvert_ca_expires_in_seconds` (signed, omitted
when no CA is loaded) and `culvert_ca_sign_failures_total`.

### FS-5 — Nil-CA reached `x509.CreateCertificate` (latent)

Found while writing the FS-1 gate. `signLeaf` dereferenced `caCert`/`caKey` without a
nil check; against the pre-fix engine `TestSignLeaf_NoCARefusesToSign` does not fail,
it **SIGSEGVs**:

```
crypto/ecdsa.(*PrivateKey).Public(0x0?)
crypto/x509.signingParamsForKey(...)
crypto/x509.CreateCertificate(...)
internal/ca.(*Manager).signLeaf(...)
```

**Not reachable today** — `handleTunnelInspect` gates on `certMgr.Ready()`, and
`caCert`/`caKey` are only ever assigned together. It is recorded as a *latent* defect,
not a live crash. The guard is worth having anyway: `signLeaf` is the chokepoint, and
making it depend on every present and future caller having checked first is the kind
of assumption that turns into an outage two refactors later. It now returns
`ErrCANotReady`.

### FS-6 — The fail-closed gate would have poisoned the auto-exclusion learner

Found while wiring FS-1, and the reason the fix is not just the gate.

When `signLeaf` starts refusing, the **client-leg** MITM handshake fails — and
`handleTunnelInspect`'s client-handshake error path calls `maybeFailOpenClient`, which
feeds `internal/autoexclude`'s learner under a fail-open decryption profile. A CA
expiry makes that handshake fail for **every host at once**, so the learner would see
a flood of "client rejected our leaf" evidence across the entire fail-open traffic
set, meet the confirm-count, and promote hosts into permanent bypass.

The result: one CA-lifecycle fault silently converts inspected traffic into bypassed
traffic — no DPI, no CDR, no file-blocking — and the exclusions **outlive the fix**,
because a learned entry is keyed on `(scopeID, gen, host)` and a CA rotation does not
change the decryption profile's security generation. Exactly the wrongful-bypass class
the autoexclude design spends its confirm-count, narrow-classifier and scope-fencing
budget avoiding.

The near miss is worth recording precisely. `classifyClientInspectFailure` matches the
token `"certificate expired"`; `ErrCAExpired` reads *"Root CA certificate **has**
expired"*. It does not match — **by one word**. A future reword of an error string
would have silently armed this.

**Fix.** `maybeFailOpenClient` returns early while the Root CA is expired. It is a
**state** check (`caExpiryState()`), not a string match, so no error-message edit can
defeat it. Scoped to *expired* only — "no CA loaded" is a different state in which
inspection is not running at all (`handleTunnelInspect` gates on `Ready()`), and
treating it the same would have broken the client leg on every node without a CA.
`TestMaybeFailOpenClient_ExpiredCADoesNotPoisonTheLearner` pins both halves: expired
CA does not learn, healthy CA still does.

**General shape, worth keeping:** *a fail-closed change alters what the error paths
downstream of it see.* Adding a refusal is never local when something else is
learning from failures.

---

## Risk Matrix

| # | Likelihood | Impact | Detection (pre-fix) | Severity | Status |
|---|---|---|---|---|---|
| FS-1 | Low-Med (needs a stalled/failed rotation, restore, or long outage) | **Critical** — all inspected HTTPS on the node | none server-side | **H** | CLOSED |
| FS-2 | Med (any CA in its final day, incl. after FS-3) | Med — over-long leaves, cache serves past CA death | none | **M** | CLOSED |
| FS-3 | **High** — every boot | Med alone; amplifies FS-1/FS-2 | none | **M/H** | CLOSED |
| FS-4 | Certain given FS-1/FS-3 | **High** — outage with no attribution | n/a | **H** | CLOSED |
| FS-5 | Very low (unreachable today) | Critical if reached (process death) | crash only | **L** | CLOSED |
| FS-6 | Would have been certain once FS-1 shipped, on any fail-open profile | **High** — silent, persistent loss of DPI/CDR/file-blocking that outlives the CA fix | none | **H** (introduced-and-closed in this change) | CLOSED |

---

## Recovery Assessment

| | Pre-fix | Post-fix |
|---|---|---|
| **Automatic** | Rotation at the next 24h tick generates a new root — which no endpoint trusts, so inspection stays broken. Illusory. | Unchanged in mechanism, but now attempted immediately at boot, so a rotatable CA is rotated before it expires rather than up to 24h later. |
| **Manual** | Possible, but the operator had to *guess* the cause from client-side TLS errors. | Alert names the condition; `/health`, `/ready`, `/metrics` and the operator contract all agree; the contract row carries the remediation (rotate, then distribute the root; bypass-rule the affected destinations in the meantime). |
| **Deterministic?** | No — outcome depended on whether anyone correlated a browser error with a proxy CA. | Yes. |

---

## Impact Assessment

**Customer.** Unchanged in the failure case (inspected HTTPS fails either way — the
client rejected the expired-issuer chain before, and the handshake now fails at the
proxy). Materially better in the *near*-failure case: an expiring CA is now caught at
boot and paged before it expires, instead of after.

**Security.** Fail-closed is preserved and made explicit. No path was added that
degrades to bypass. The clamp removes a window in which a cached leaf outlived the
trust backing it.

**Operational.** The outage becomes attributable within one alert. `/ready?strict=1`
users get an ejection signal for the condition; default `/ready` users do not, on
purpose.

**Data integrity.** None (no persistence touched).

**Performance.** Two comparisons and a `min` on the cache-miss signing path only;
cache hits are untouched. `certMgr.CAExpiry()` is an `RLock` read at scrape time.

---

## Required Tests

All shipped. Every gate below was run against the pre-fix engine to confirm it fails.

**`internal/ca/ca_expiry_test.go`**

| Test | Pre-fix result |
|---|---|
| `TestSignLeaf_ExpiredCARefusesToSign` | FAIL — *"signLeaf issued a leaf from an EXPIRED Root CA (fail-open)"* |
| `TestGetCert_ExpiredCASurfacesTheRefusal` | FAIL — `GetCert error = <nil>` |
| `TestSignLeaf_NeverOutlivesIssuer` | FAIL — *"leaf NotAfter 2026-08-09 … outlives issuer NotAfter 2026-08-08 …"* |
| `TestSignLeaf_NoCARefusesToSign` | **SIGSEGV** |
| `TestSignLeaf_HealthyCAUnaffected` | pass (no-regression half: healthy leaf still chain-verifies, zero sign failures) |
| `TestCACertInfo_ExpiryIsExplicit` | FAIL — field absent |

**`ca_expiry_test.go` (package main)** — latch escalation and re-arm, silence with no
CA, `caExpiryState` distinguishing expired from absent, the immediate first rotation
round, the rotate-then-evaluate ordering, alert-detail actionability, `/health` +
`/ready` rows, `checkRootCA` verdicts, the two new metric series (including the
gauge's absence when no CA is loaded), and
`TestMaybeFailOpenClient_ExpiredCADoesNotPoisonTheLearner` (FS-6: expired CA must not
learn; healthy CA still must).

---

## Residual Risk

1. **Rotating the Root CA does not restore inspection on its own.** The new root must
   reach endpoint trust stores. Culvert cannot do that for the operator; it now says
   so in the alert and the contract row. See §6 — this is the same underlying issue.
2. **The latch resets on restart**, so a crash-looping node re-fires one alert per
   start at the current level. Deliberate and consistent with the CHAOS-12 and
   release-catalog latches; the alternative (persisting latch state) trades a bounded
   duplicate for a durable way to *lose* an alert.
3. **Thresholds are constants** (30d / 7d), matching `caRotationOverlap`. Recorded
   deferral, same class as the release-catalog thresholds.
4. **`SaveCA` failure during rotation is still swallowed** (register row CA-2). It is
   now *detectable* — the CA that never persisted reloads near-expiry after a restart
   and the expiry watch fires within the first round rather than 24h later — but the
   silent-success bug itself is untouched. Left for a CA-2 pass.
5. **Clock rollback** past the CA's `NotBefore` is not covered. `signLeaf` guards
   `NotAfter` only; a large backwards jump produces leaves a client sees as not-yet-
   valid (register row CA-10 covers the leaf-vs-UI-cert backdate asymmetry).
6. **Dual-CA overlap** is unchanged and is not what it claims (§6).

---

## §6 — Recorded, not fixed: dual-CA overlap does not bridge client trust

`RotateIfNeeded` keeps the old CA as `secondaryCACert` and `signLeaf` appends its DER
to the served chain, with the intent (per the code comment) that *"leaf certs signed
by either CA remain valid during the transition."*

The leaf is signed by the **new** CA. Appending the **old** root to the chain does not
help a client validate it — the old root is not the leaf's issuer, and the new root is
not in any endpoint's trust store yet. A client trusting only the old CA fails
validation exactly as it would with no overlap at all. The overlap window therefore
provides no client-trust continuity; what it actually preserves is the old key's
availability inside the process.

Making this real needs a design decision, not a repair — cross-sign the new root with
the old CA key, or keep signing with the old CA until it expires while the new root is
distributed out-of-band. Either changes the trust model and belongs in an ADR.

Scoped out of CHAOS-30 deliberately: it is a latent design gap on a 10-year clock,
while FS-1 through FS-4 are live defects reachable this week. Raised as a new register
row **CA-16**.
