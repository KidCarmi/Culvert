# Chaos Engineering Review — 2026-08-09

**Domain:** the SSL-inspection Root CA across its full lifecycle — expiry, clock skew and
rollback, rotation, rotation persistence, and the leaf cache under steady-state load.
**Register items:** CHAOS-28 (new) · closes standing rows **CA-1**, **CA-2**, **CA-4**;
adds and closes a previously unrecorded cache leak.
**Verdict:** four confirmed defects, all fixed, every regression gate proven to fail against
the pre-fix code.

---

## Executive Summary

The Root CA was reviewed as a **time bomb with no fuse indicator**. Every other security
control in Culvert fails in a way the appliance can observe: a dial fails, a scanner times
out, a write returns `ENOSPC`. The inspection CA is the one control whose failure produces
*no error anywhere inside the process*. It expires, the engine keeps signing, and the only
entity that notices is the client — which reports it as a per-site certificate warning that
looks like a website problem, not a gateway problem.

The trigger is not exotic. It is reached by any of: an appliance powered off through its
30-day rotation window; a rotation that ran but could not write its bundle; a node restored
from a backup older than the window; a `-ca-path` bundle imported from a peer that was
already near expiry; or simply a deployment that outlives its CA. The register already
carried the headline finding (**CA-1**, High) — this sweep confirmed it is still live on
`main`, and found that it is worse than recorded in three separate ways.

| # | Failure mode | Class | Why the existing design did not cover it |
|---|---|---|---|
| 1 | Expired Root CA **keeps signing** leaves every client rejects | Silent fail-broken → fleet-wide outage | `x509.CreateCertificate` never checks the parent's validity, and nothing else did either |
| 2 | Leaf `NotAfter` **not clamped** to the issuer's | State corruption / undiagnosable incident | leaf lifetime was an unconditional `now+24h`, independent of the CA |
| 3 | Rotation that **cannot persist** reports success | Fake recovery | `SaveCA` error was logged and discarded; `RotateIfNeeded` returned `true` regardless |
| 4 | Leaf-cache order slice **grows per TTL refresh**, unbounded | Resource exhaustion scaling with uptime | eviction keys on *map* length; the map is bounded, the slice was not |

\#1 and \#2 are the outage. \#3 is why the outage can survive the fix an operator applies to
it. \#4 is unrelated to expiry and was found in the same file — an unbounded slice behind a
bounded map, growing on the most ordinary workload there is.

Everything here is now fail-closed, counted, alerted, and visible on `/healthz`, `/readyz`,
`/metrics` and the CA Management panel.

---

## Failure Scenarios

### FS-1 — The expired Root CA that never stopped signing

**Current behavior (pre-fix).** `signLeaf` read `cm.caCert` and signed:

```go
certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &leafKey.PublicKey, caKey)
```

No validity check on `caCert`, at any layer. And crucially, **the standard library does not
supply one**: `x509.CreateCertificate` validates the parent's key usage and the key pair, not
its `NotBefore`/`NotAfter`. This is not an inference — the regression gate
`TestSignLeaf_RefusesExpiredCA` was run against the pre-fix engine and the sign *succeeded*,
returning a well-formed certificate from a CA that expired an hour earlier.

The dispatcher's gate did not help either. `handleTunnel` (proxy_tunnel.go) branched on:

```go
if dec.Action == SSLInspect && certMgr.Ready() { ... }
```

and `Ready()` is `caCert != nil`. An expired CA is loaded, so `Ready()` is `true`, so every
inspect-matched CONNECT proceeded, hijacked the connection, and presented a leaf chained to a
dead issuer.

**Expected behavior.** A security control that cannot perform its function refuses, loudly,
in one place — rather than emitting output that cannot work, N times, silently.

**Failure mode.** Total inspected-HTTPS outage. Every client on every inspect-matched
destination gets `SEC_ERROR_EXPIRED_ISSUER_CERTIFICATE` / `certificate has expired`, which
users and helpdesks read as "that website is broken", not "the gateway's CA expired". The
1-hour leaf cache does not soften it: a cached leaf is still chained to the expired root.

**Blast radius, precisely.** The failure is *fleet-wide and simultaneous* on any cluster
provisioned from one bundle, because every node holds the same CA with the same `NotAfter`.
There is no canary, no partial degradation, no staggering.

**Monitoring visibility (pre-fix).** None that moves.

| Signal | Pre-fix state during the outage |
|---|---|
| `/healthz` `ssl_inspection` | `"ready"` — `Ready()` only asks whether a CA is loaded |
| `/readyz` `ca` row | `ok` |
| `culvert_ca_rotations_total` | unchanged (counts successes only) |
| `culvert_cert_cache_*` | ticking normally — the engine was signing happily |
| Alerts | none; `cert_expiry` fires on *rotation*, not on expiry-reached |
| Logs | none |

The single closest thing to a signal was `ca_expires_days` inside the `/healthz` JSON body —
a field no alerting rule evaluates and no dashboard plotted, and which in any case only helps
*before* the cliff.

**Post-fix behavior.** Three layers, outermost first:

1. `handleTunnel` calls `certMgr.Usable()` and, on failure, `failClosedUnusableCA` → **502
   before the CONNECT is answered 200**, so the client gets a proxy error it can attribute to
   the proxy, not a hijacked socket that then fails TLS for reasons it cannot see.
2. `signLeaf` refuses with `ErrCAUnusable` — defense in depth for every other `GetCert`
   caller and any future one.
3. The refusal fires `ca.UnusableObserver` → `ca_health.go`: counters, a rate-limited log
   line naming the remediation, and a rate-limited `cert_expiry` alert.

**Why fail CLOSED and not bypass.** This was the load-bearing decision of the change, and the
tempting fix is the wrong one. Folding expiry into `Ready()` — one word of diff — would route
an expired CA into the existing `inspect_unavailable` bypass branch, and traffic would keep
flowing. It would also mean that **the moment the CA expires, the entire fleet silently stops
inspecting**: DLP, ClamAV, YARA, CDR, file-blocking and DPI all dark, on every host at once,
with the gateway reporting itself healthy. That converts an availability failure into a
security-control failure, which is strictly worse for an appliance whose reason to exist is
inspection — and it is precisely the "silent fail-open degradation" this register names as
its number-one cross-cutting theme (§1).

The same argument rules out honouring a decryption profile's `OnInspectError=fail-open`. That
contract is scoped to **per-origin** TLS incompatibility and is deliberately gated behind a
confirm-count of distinct client evidence before a single host is excluded. An expired CA is
**host-independent**: routing it through the learner would promote every host requested during
the outage into a durable bypass, poisoning the cache from one appliance-level fault. So the
unusable-CA path never learns, never rescues, and never bypasses — documented at the call site.

The availability cost of failing closed is **zero relative to the pre-fix state**: a leaf
chained to an expired issuer already fails path validation in every mainstream client. The
traffic was dead either way. What changes is that the appliance now knows, says so, and points
at the fix.

### FS-2 — Leaves that outlive their issuer

**Current behavior (pre-fix).** `NotAfter: time.Now().Add(24 * time.Hour)`, unconditionally.

**Failure mode.** In the CA's final 24 hours, every forged leaf claims validity past its own
issuer's. RFC 5280 path validation evaluates every certificate in the chain at the time of
use, so such a leaf is never *more* useful than a clamped one — but it is considerably harder
to diagnose. The leaf looks valid to `openssl x509`, only the chain fails, and the failure
appears to move around as different clients revalidate at different moments. It is the shape
of incident that costs an on-call engineer an hour before they think to check the root.

The mirror case also existed: leaves are backdated 5 minutes, so a leaf minted immediately
after a rotation could claim a `NotBefore` earlier than the CA that signed it.

**Post-fix.** `clampLeafValidity` narrows the leaf window to the issuer's on both ends. The
FS-1 guard guarantees `now < caCert.NotAfter`, so the clamped window is always non-empty.

### FS-3 — The rotation that reported success it did not achieve

**Current behavior (pre-fix).**

```go
if err := cm.SaveCA(caPath, passphrase); err != nil {
    obs.Printf("CA auto-rotation: save failed: %v", err)
}
// …unconditionally logs "new CA generated", fires RotationObserver, returns true
```

**Failure mode.** On a full, read-only, or permission-denied data volume the replacement CA
exists **only in RAM**. The operator is told the CA rotated, and the `cert_expiry` alert
confirms it. Then:

- the next restart reloads the **old, near-expiry** bundle;
- the startup check rotates again, producing a **different** root;
- every client provisioned with the previous replacement now distrusts the gateway;
- and the cycle repeats on every boot.

Rotation is the *only* recovery path FS-1 has. A recovery path that silently does not persist
is worse than no recovery path, because it consumes the operator's belief that the problem is
solved.

**Post-fix.** `RotationPersistFailureObserver` fires, the success log is replaced with an
explicit "NOT PERSISTED — it exists in memory only" line, a `cert_expiry` alert describes the
state, `culvert_ca_rotation_persist_failures_total` counts it, and the CA panel shows an
amber banner. Rotation still returns `true` (the in-memory CA *is* now the active one, and
lying in the other direction would suppress the observer that reports it), but nothing
downstream can any longer mistake it for a durable rotation.

### FS-4 — The cache-order slice that grew with uptime

**Current behavior (pre-fix).** `GetCert` appended to `cacheOrder` on **every** miss:

```go
cm.cache[host] = &certCacheEntry{cert: cert, createdAt: now}
cm.cacheOrder = append(cm.cacheOrder, host)
if len(cm.cache) > certCacheMaxSize { /* evict */ }
```

A TTL-expired **refresh** of an existing host *overwrites* the map entry, so `len(cm.cache)`
does not change and the eviction branch never fires — while the slice grew by one string.

**Failure mode.** Unbounded memory growth on the most ordinary workload there is: a steady
working set. With `certCacheTTL = 1h` and a working set of W hosts, the slice grows by W
entries per hour, forever. At W = 5,000 that is ~120,000 strings/day (~4.4 M/year); the map it
indexes stays pinned at its 10,000-entry cap the whole time. The leak scales with **uptime**,
which is the axis an appliance is specifically supposed to be good at, and it is invisible to
`culvert_cert_cache_size` (which reports the bounded map).

The duplicates were dead weight for eviction as well: the second and later copies of a host
always resolved to "already gone" and were skipped. Dropping them changes no eviction
decision — the first insertion still governs — so the fix is behavior-preserving.

**Post-fix.** `cacheOrder` is appended only for a host not already tracked. Pinned by
`TestGetCert_CacheOrderDoesNotGrowOnRefresh` (25 refreshes of one host ⇒ 1 order entry;
25 pre-fix) and its negative control for distinct hosts.

### FS-5 — Clock skew and clock rollback (assessed; guarded)

A node whose clock is stepped **backwards** past the CA's `NotBefore` is in the mirror of
FS-1: leaves it signs are "not yet valid". `caUsable` treats it the same way — refuse, count,
alert — with a 5-minute tolerance so a peer with a slightly fast clock, or a CA generated
seconds ago, cannot take the gateway down. The tolerance matches the backdating already
applied to leaves, so both ends of the window use one constant.

### FS-6 — The 24-hour blind spot in front of the only recovery path

**Current behavior (pre-fix).** `StartCAAutoRotation` created a 24-hour ticker and entered
`select` — the **first** expiry check happened 24 hours after boot.

**Failure mode.** The check is skipped exactly when it matters. An appliance powered off
through its rotation window, or restarted *by an operator trying to recover from the expiry
outage*, sits for another full day doing nothing while every inspected request fails. Register
row **CA-4**.

**Post-fix.** One guarded round runs immediately, before the ticker. `RotateIfNeeded` is a
no-op outside the 30-day window, so on a healthy node the cost is a single expiry comparison
at startup. The CHAOS-24 per-round panic containment is preserved (the round body was
extracted into a closure used by both the immediate call and the ticker, so the two can never
drift apart).

---

## Risk Matrix

| ID | Scenario | Pre-fix severity | Likelihood | Detectability (pre) | Status |
|----|----------|------------------|------------|---------------------|--------|
| FS-1 | Expired Root CA keeps signing | **Critical** — fleet-wide inspected-HTTPS outage | Certain at CA end-of-life; reachable early via restore/import/power-off | **None** | CLOSED |
| FS-3 | Rotation persists nowhere, reports success | **High** — recovery is fake, new root per boot | Any full / read-only / RO-mounted data volume | Log line only, discarded | CLOSED |
| FS-6 | 24h blind spot before first rotation check | **High** — delays the only recovery | Every restart inside the window | None | CLOSED |
| FS-2 | Leaf outlives issuer | **Medium** — corrupt-looking state, long MTTR | Certain in the CA's final 24h | None | CLOSED |
| FS-4 | `cacheOrder` unbounded growth | **Medium** — memory exhaustion scaling with uptime | Certain on any steady-state workload | None (`cache_size` reports the bounded map) | CLOSED |
| FS-5 | Clock rollback past `NotBefore` | **Medium** — same outage shape as FS-1 | NTP step / bad RTC on boot | None | CLOSED |

---

## Recovery Assessment

| | Pre-fix | Post-fix |
|---|---|---|
| **Automatic recovery** | Rotation, but only ≥24h after boot (FS-6) and possibly non-durable (FS-3) | Rotation checked at startup **and** every 24h; a non-durable rotation is reported, not hidden |
| **Manual recovery** | Possible but undiscoverable — nothing named the CA as the cause | `/healthz` `ssl_inspection: expired`, `/readyz` `ca: fail`, `culvert_ca_usable 0`, a `cert_expiry` alert naming the impact, and a red CA-panel banner with the remediation |
| **Recovery evidence** | n/a | Degraded state clears **only** on an observed usable verification (`caInspectionUsable`) — silence is never treated as recovery |
| **Residual manual step** | — | Redistributing the new root CA to clients. Unavoidable: a new root is untrusted by definition, and no in-band mechanism can fix that |

The last row is the honest limit of this work. Rotation restores the appliance's *ability* to
inspect; it cannot restore *client trust*. That is why the fix invests so heavily in making
the condition visible **before** the cliff (`culvert_ca_expires_in_seconds`) rather than only
at it.

---

## Operational Impact

- **On a healthy node: none.** One expiry comparison per CONNECT dispatch (a pointer read plus
  two `time.Time` compares under `RLock`), one comparison at startup, and one fewer `append`
  per cache refresh. No new goroutine, no allocation, no lock added.
- **During the outage:** requests fail with 502 instead of hanging in a doomed TLS handshake,
  which frees the connection promptly rather than tying up a goroutine, a pooled 128 KB relay
  buffer and two sockets until a client timeout.
- **Log volume is bounded.** An expired CA fails *every* inspected request; both the log line
  and the alert are behind independent 5-minute gates, on the storage-health model. The
  counters carry the magnitude that rate limiting drops.
- **Alert volume is bounded twice.** The producer is also `HasSubscriber`-gated, so a node
  with no webhooks configured — the default posture — never spawns a delivery goroutine, per
  the per-request alert-producer contract.

---

## Security Impact

- **The primary security property preserved is that the fix does not create a bypass.** The
  full argument is in FS-1; the negative assertion is executable
  (`TestHandleTunnel_ExpiredCAFailsClosedNotBypass` fails if the outcome is ever recorded as
  any flavour of bypass rather than `failed` / `no_fail_open_502`).
- **The auto-exclusion cache is not poisoned.** The unusable-CA path sets no learner field;
  pinned by both the projection test and the end-to-end dispatcher test.
- **No new information disclosure.** The 502 body carries no detail; the `/readyz` row — an
  unauthenticated surface on the proxy port — carries a fixed string, not the CA's exact
  `NotAfter`, which would fingerprint a security-degraded node to any client that can reach
  the proxy. The full cause goes to the logs, the alert, `/healthz` (`redact:"internal"`) and
  the role-gated admin API. Asserted, not assumed.
- **Metrics stay label-free**, per the CA-2 contract: no SNI host, SAN, subject, serial,
  fingerprint or key material — counts and one time delta.

---

## Suggested Improvements (shipped in this PR)

| Change | File |
|---|---|
| `Usable()` / `caUsable` validity predicate + `ErrCAUnusable` + skew tolerance | `internal/ca/validity.go` |
| `signLeaf` refuses an out-of-window CA; leaf validity clamped to the issuer | `internal/ca/ca.go` |
| `cacheOrder` append only for untracked hosts (unbounded-growth fix) | `internal/ca/ca.go` |
| Rotation persist failure observed and reported, not swallowed | `internal/ca/ca.go` |
| Health plane: counters, evidence-based recovery, rate-limited log + alert | `ca_health.go` |
| Fail-closed CONNECT dispatch + ADR-0011 failure outcome | `proxy_tunnel.go`, `decryption_observability.go` |
| Immediate startup rotation check (CA-4) | `ca.go` |
| `culvert_ca_usable` · `_expires_in_seconds` · `_sign_refused_total` · `_inspect_blocked_total` · `_rotation_persist_failures_total` | `ca_metrics.go` |
| `/healthz` `ssl_inspection: expired`; `/readyz` `ca` row (report-only, strict-gating) | `healthcheck.go` |
| `GET /api/ca/status` usability fields + CA-panel banners | `ui_security.go`, `static/index.html` |

---

## Required Tests (shipped)

Every gate below was executed against the pre-fix code and **observed to fail**; the failure
output is quoted in the PR description.

**`internal/ca/validity_test.go`**
- `TestCAUsable_ValidityWindow` — 7 cases: inside window, either side of expiry, long expired,
  no CA, clock rollback within/past tolerance.
- `TestSignLeaf_RefusesExpiredCA` — refusal + `ErrCAUnusable` + counter + observer.
- `TestGetCert_ExpiredCADoesNotServeOrCache` — the `GetCertificate` callback refuses and the
  failed sign leaves no cache entry to be served later.
- `TestSignLeaf_ClampsLeafValidityToIssuer` / `TestSignLeaf_ClampsNotBeforeUpToFreshIssuer`.
- `TestGetCert_CacheOrderDoesNotGrowOnRefresh` + `TestGetCert_CacheOrderTracksDistinctHosts`.
- `TestRotateIfNeeded_PersistFailureIsReported` (parent path is a regular file ⇒ every write
  fails `ENOTDIR`) + `TestRotateIfNeeded_SuccessfulPersistIsSilent` (no crying wolf).

**`ca_expiry_failclosed_test.go`** (package main)
- `TestHandleTunnel_ExpiredCAFailsClosedNotBypass` — **the security gate**: 502, no CA detail
  in the body, ADR-0011 outcome `failed`/`no_fail_open_502`/`client_hello`/`certificate`, no
  learner fields, counter and degraded state set.
- `TestHandleTunnel_ValidCAIsUnaffected` — negative control.
- `TestHealthz_ExpiredCAIsNotReported_Ready`, `TestReadyz_ExpiredCARowIsReportOnly` (including
  the no-timestamp-leak assertion and the strict-mode 503).
- `TestCAUsabilityMetrics` — series present, negative seconds once expired, series **omitted**
  entirely with no CA loaded.
- `TestCAUnusable_AlertAndLogAreRateLimited` — 500 faults ⇒ 1 alert, counter still 500.
- `TestCAUsabilityDegraded_RecoveryNeedsEvidence` — clears only on an observed verification.
- `TestCAUnusableOutcome_Projection`, `TestCARotationPersistFailure_IsAlerted`.

---

## Residual Risk

1. **Client trust redistribution remains manual.** Rotation restores signing; it cannot make
   clients trust a new root. Mitigated only by early warning
   (`culvert_ca_expires_in_seconds`) — operators should alert on it well before 30 days.
2. **The leaf-cert cache has no single-flight** (register row **CA-11**, still open). N
   concurrent misses for one host each sign independently, and TTL expiry is synchronised, so
   a mass reconnect storm produces a herd. The perf-F3 shared leaf key removed the dominant
   cost (P-256 keygen), so this is materially smaller than when first recorded — left open and
   re-scoped rather than folded into a fail-closed change.
3. **Cluster CA rotation still fails silently** (register row **CA-13**): every failure branch
   in `enrollment.go` logs and returns with no alert or metric. Same defect class as FS-3, in
   the *other* CA. Deliberately out of scope here — the cluster CA has a different lifecycle
   and blast radius (enrollment, not inspection) and deserves its own sweep. Suggested next.
4. **`caUsable` reads wall-clock `time.Now()`**, so a clock stepped *forward* past the CA's
   `NotAfter` produces a false outage until the clock is corrected. This is the correct
   direction to fail (a client with the same wrong clock would reject the chain anyway), but
   it means NTP misconfiguration can present as a CA incident. The alert text names the
   violated bound and the timestamp, which is what disambiguates it.
5. **Startup rotation is not jittered.** A fleet restarted simultaneously inside the 30-day
   window will each rotate at once. Each node's inspection CA is node-local (no shared
   bundle write), so there is no contention — but it does produce a burst of `cert_expiry`
   alerts. Accepted; the pre-existing 24h tick had the same property.
