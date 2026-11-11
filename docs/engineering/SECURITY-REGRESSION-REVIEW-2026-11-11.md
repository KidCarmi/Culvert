# Security Regression Review — 2026-11-11

**Scope.** `ac4e223…04aa647` (`origin/main`) — the window since the 2026-11-10
review, 10 merged pull requests (#1854 #1856 #1857 #1858 #1859 #1860 #1861
#1862 #1864 #1865), 52 files, +4,668/−143.

| PRs | Change | Security surface |
|---|---|---|
| **#1854** | `feat(ca)`: provenance decides who may renew the inspection CA; renewal re-issues the SAME key and subject; an intermediate primary is now served with the leaf | **inspection-CA trust lifecycle** — automatic replacement of an operator-owned trust anchor, CA-expiry fail-closed, chain building |
| **#1862** | CHAOS-116: the ClamAV status ping becomes a bounded, single-flight, off-caller probe (`PingContext`) | **unauthenticated amplification into the AV daemon → node-wide scanning fail-open**; liveness/readiness honesty |
| **#1861** | `perf(catdb)`: one BadgerDB read transaction per category lookup instead of one per label | **category-policy data path** — key aliasing, store-fault classification, per-decision read consistency |
| **#1859** | `fix(uitls)`: drop DNS SANs x509 cannot encode instead of failing the whole self-signed cert | **cleartext admin UI** — one operator typo in `-ui-san` downgraded the admin plane to plain HTTP |
| **#1864** | `build(go)`: toolchain go1.27.3 → go1.27.4 | **GO-2026-6859 in `net/http`**, reachable from header handling and `http.Client.Do` |
| **#1860** | `internal/pseudonym.MintID`, plus the 2026-11-10 review and its three comment corrections | destination-redaction generation identity; the 429 → fail-CLOSED comment barrier on `scanOnce` |
| **#1858** | diagnostics row for a CDR pool with tripped circuit breakers | **document-sanitization capacity** visibility (breaker state read-only) |
| **#1856** | rename `culvert_scan_svc_at_capacity_total` → `culvert_scan_svc_saturated_total` | monitoring contract for a fail-CLOSED refusal counter |
| **#1865** | wait for the ClamAV status probe before restoring test globals | test determinism only |
| **#1857** | documentation governance review (no findings) | none |

**Question asked.** Not "is the change good?" but the inverse: **did it weaken
the posture that existed at `ac4e223`?** Every verdict below is measured against
that revision, not against an ideal.

**Method.** Two changes in this window alter what the gateway *does* with trust
material or with a security control's health signal, and those took the weight.
#1854 withdraws an automatic action (renewal) from CAs it no longer claims
authority over, so the load-bearing question is not whether withholding is
correct but **what happens at the expiry it now allows to arrive** — that was
traced from `RotateIfNeeded` through `signLeaf`'s `caUsable` guard into the
`tls.Config.GetCertificate` callbacks, because a bypass there would convert a
visible outage into silent plaintext. #1862 moves an unauthenticated code path
onto a detached goroutine, so its answer-under-uncertainty was checked against
both consumers (`coarseClamAVStatus`, `computeReadiness`) rather than against
its own comment, and its lock order and single-flight were read for the states
its comments do *not* claim. #1861 is a performance refactor on the policy data
path whose safety argument rests on a claim about badger's internals, so the
claim was read as a claim.

Claims that mattered were **executed or traced to source, not taken from a
comment**: the window's gates were run at this SHA (`go build ./...` clean;
`internal/ca`, `internal/catdb`, `internal/clamav`, `internal/secscan`,
`internal/pseudonym`, `internal/uitls` all pass under `-race`; `internal/secscan`
also under `-race -shuffle=on -count=2`; the root tests this window added pass;
the `benchgate` tag passes for `internal/catdb` and `internal/secscan`;
`golangci-lint` v2.15.0, the version the Fast PR Gate installs, reports 0 issues
on the changed package; `docs/agent-context/check.py` passes). The CA-expiry
fail-closed chain was followed to `GetCertificate`; `cdrCircuitBreaker.State()`
was read to confirm it is a pure atomic load and not a state-machine step; and
the status probe's reconfigure behaviour was **reproduced in a test** rather
than reasoned about, which is finding A.

**No security regression. Two findings, both Low, both fixed here. Six
residual risks recorded, two of them introduced by this window and accepted.**

---

## Executive Summary

**No change in this window weakened the posture that existed at `ac4e223`, and
four of them strengthen it materially.**

The CA provenance change (#1854) is the largest and the one most easily
mistaken for a regression, because it **removes** an automatic action: a CA
Culvert did not generate is no longer renewed on its own. That reads like a
withdrawal of availability protection, and it was checked as one. It is not a
regression, for two reasons that both had to hold.

First, what the old behaviour actually did. Auto-rotation generated a **fresh
key** and a fresh self-signed certificate. A leaf is verified with its issuer's
public key, so after that rotation every client — including every client that
trusted the imported customer root, and in fact *all* clients, since the new
root had not existed a moment earlier — rejected every inspected connection.
The old path did not preserve inspection through expiry; it replaced an
operator-owned trust anchor with a self-signed one and broke inspection anyway.
#1854 keeps the key and the subject on renewal (`installSelfSignedCA(oldKey,
oldCert.RawSubject)`), which is what makes the dual-CA overlap real for the
first time, and declines to perform the replacement at all where the trust
relationship is not Culvert's.

Second, where the newly-reachable expiry leads. It leads to a refusal, not a
bypass, and that was traced rather than assumed: `signLeaf` calls
`caUsable(caCert, now)` before minting, counts the refusal, fires
`UnusableObserver`, and returns an error; the only production callers are the
`GetCertificate` callbacks in `proxy_tunnel.go:664` and
`proxy_tunnel_h2.go:343`, so the error fails the TLS handshake. There is no
fallback-to-tunnel leg on that path. The operator-facing claim in
`docs/operator/root-ca-expiry.md` — "At expiry inspected HTTPS is **refused**
(§1), never bypassed" — holds at this revision.

Authority is taken from a **record** written inside the bundle, never from the
certificate's name or self-signed status, which is the right primitive: a
customer root is self-signed too. Every load path converges on
`installCALocked`, so the record is applied consistently —
`LoadCA` → `ImportBundle` (startup and the recovery loop),
`restore.go:650` → `ImportBundle` (backup restore), `LoadCustomCA`
(admin upload ⇒ `imported`), `InitCA`/`installSelfSignedCA` (⇒ `culvert-managed`).
`ParseProvenance` fails toward `ProvenanceUnknown`, and unknown means **do not
renew** — the conservative direction. An unrecognised `CULVERT_CA_PROVENANCE`
is logged through `sanitizeLog` with `%q` and ignored. No admin-reachable
endpoint installs a bundle whose embedded record could mislabel an imported CA
as managed: the admin upload path is `LoadCustomCA`, which hardcodes `imported`.

CHAOS-116 (#1862) closes a genuine unauthenticated amplification. `/health` and
`/ready` are dispatched on the **proxy** listener ahead of the IP filter, the
rate limiter and the connection limiter, and on a cache miss they used to run
`clam.Ping()` inline — a `context.Background()` dial under roughly twice the
30 s scan budget, with no single-flight and taking no `clamSem` slot. Since a
ClamAV connection failure is classified as an engine fault and forwards content
**unscanned**, a request flood against an unauthenticated endpoint could
suppress malware scanning node-wide. The fix bounds the probe at 5 s, bounds the
caller at 750 ms, coalesces every concurrent reader onto one dial, and answers
"not yet observed" only before any observation exists. That answer is
fail-closed on both consumers, which was verified: `coarseClamAVStatus`
collapses it to `unreachable`, and `computeReadiness`'s `clamav` switch takes
its `default` branch and sets `allOK = false`. Failure observations are cached
with the same TTL as successes, so a dead daemon is dialed at most once per 30 s
per process.

The one defect this review found is in that change, and it is **latent**:
the single flight has no notion of configuration generation, so a reconfiguring
`Init` joins the flight already dialing the *previous* daemon (finding A). It is
fixed here with a generation guard and four gates. `loadScanning` is the only
`Scanner.Init` caller and runs once at startup, so there is no production
precondition today — but `Init`'s own comment anticipates the runtime
reconfigure caller that would make it live, and the defect's direction is the
unsafe one: a stale `connected` keeps a node in rotation while its scans fail
open.

#1859 is a quietly important availability-of-confidentiality fix: a single
non-ASCII DNS SAN (an IDN typed as-is instead of punycode) in `-ui-san`,
`ui_sans` or `CULVERT_PUBLIC_IP` made `x509.CreateCertificate` reject the
**whole** certificate, and the admin UI treats a self-sign failure as "serve
plain HTTP" — admin credentials and session cookies in cleartext on the next
start. Dropping the unencodable name narrows the SAN set and never widens it,
and IA5 encodability is in fact the only constraint `CreateCertificate` places
on a DNS SAN, so the filter is neither too narrow nor too broad.

#1861 touches the policy data path, and its safety argument is a claim about
badger that the comment states precisely and correctly: the walk reuses one
`[]byte` and only ever **narrows** it, `Txn.Get` retains the caller's slice as
`item.key`, the `Item` never outlives `getExact`, and the value is copied inside
`item.Value`'s callback. Since the transaction is read-only, nothing writes to
that array, so the aliasing is benign — and a future change that wrote into the
key in place would break it, which the comment says. Fault classification is
byte-for-byte equivalent to the previous shape (`ErrKeyNotFound` ⇒ clean miss;
anything else ⇒ returned for the caller to count and latch), and collapsing to
one read timestamp makes a categorisation decision immune to a half-visible
feed `BulkWrite`.

#1864 is a straight security fix: GO-2026-6859 in `net/http`, reachable from
this module, fixed in go1.27.4, with the `go.mod` toolchain line and all three
builder images moved together as the consistency gates require.

**Nothing in this window touched authentication, session handling, cookie
flags, CSRF, RBAC, audit, or configuration versioning.** The admin surfaces it
did touch (`apiCAStatus`'s `autoRotation`, the `cdr` diagnostics row) keep their
handler-level `requireRole` checks and remain read-only.

---

## Security Findings

### A — CHAOS-116's status single-flight has no configuration generation (Low, latent, fixed here)

**Affected contract.** `internal/secscan.Scanner.Init`'s stated invariant:
"Invalidate any cached clam status so the next status read reflects the daemon
configured now, **never the previous one**." And the consumer contract that a
`connected` status means *this node's* configured ClamAV answered.

**Defect.** `startClamStatusProbe` joins any in-flight probe. `Init` clears the
status cache, installs a new `*clamav.Client` for the new address, and then
"warms" the cache with the same single-flight probe. If a probe is already in
flight against the **previous** daemon:

1. the warm-up **joins that flight**, so the newly configured address is never
   probed at all; and
2. when the old daemon answers, `runClamStatusProbe` stores its observation
   under the new configuration with a full `clamStatusTTL` (30 s), and logs it
   with the **new** address, because it reads `ss.clamStatusAddr` at store time.

Reproduced before the fix: a gated "healthy" probe in flight, then
`Init("127.0.0.1:1", …)`, produced `ClamAVStatus() == "connected"` and the log
line `SecurityScan: ClamAV connected at "127.0.0.1:1"` for a port nothing
listens on.

**Attack scenario / failure scenario.** Not attacker-triggered: `Init` is
privileged. The failure is an operator one. An admin repoints ClamAV (or a
future runtime reconfigure fires) while a probe is mid-dial against the old
daemon; for up to 30 s the node publishes `connected` on `/ready` and
`/health`. `computeReadiness` keeps the `clamav` row green, the orchestrator
keeps the node in rotation, and every body scan on that node fails with a
connection error — which `internal/secscan` classifies as an engine fault and
forwards **UNSCANNED** (`statClamScanError`, fail-open). The transition log line
actively misdirects the investigation by naming the address that was never
probed.

**Preconditions.** A second `Scanner.Init` call with a probe in flight (≤ 5 s
window per probe).

**Exploitability.** None directly — no unauthenticated or unprivileged trigger.
**Likelihood.** Low today: `loadScanning` is `Init`'s only caller and runs once
at startup (`main.go:265`), so the window does not occur in a shipped
deployment. **Regression risk.** Medium the moment a runtime reconfigure caller
is added, which `Init`'s doc comment explicitly anticipates.

**Impact.** Monitoring and readiness report a security control as healthy while
it is down and failing open. No enforcement decision is changed directly.

**Affected assets.** Malware-scanning coverage on a node; `/ready` and
`/health` fidelity; operator response time during an AV outage.

**Fix (applied).** `Scanner.clamStatusGen` (`atomic.Uint64`), bumped by `Init`
beside the cache clears. `startClamStatusProbe` captures the generation and
coalesces **only** onto a flight of the same generation, so a reconfiguring
caller starts its own probe for the daemon configured now; the deferred cleanup
clears `clamProbeDone` only if it still owns the handle, so a superseded probe
finishing later cannot erase the current flight. `runClamStatusProbe` compares
the generation under `mu` before storing and **discards** a superseded
observation without storing or logging it — so callers fall back to
`clamStatusUnknown`, which fails readiness, until a probe for the configured
daemon lands. Fail-closed in the uncertain direction, and the dial rate stays
bounded by the reconfigure rate rather than the request rate.

**CWE.** CWE-672 (operation on a resource after expiration/release) with
CWE-367 (TOCTOU) flavour; the consequence is CWE-754 (improper check for an
unusual condition) on the readiness surface.
**OWASP.** A09:2021 Security Logging and Monitoring Failures.
**Severity.** Low (latent; no production precondition today).

### B — `CULVERT_CA_PROVENANCE` was absent from the README environment reference (Low, fixed here)

**Affected contract.** README §"Environment variables" is the canonical
inventory of Culvert's environment configuration; `CULVERT_CA_PASSPHRASE` and
`CULVERT_SESSION_SECRET` are there.

**Defect.** #1854 introduced the one control that restores automatic CA renewal
on an upgraded install, and documented it in
`docs/operator/root-ca-expiry.md` §5 and the CHANGELOG — but not in the
environment table an operator reads when writing a deployment manifest.

**Failure scenario.** An operator upgrades, their bundle loads as *unknown*, and
their Culvert-generated root is never renewed. The startup log and the 24-hourly
`cert_expiry` alert do say so, so this is a slow, announced failure — but the
operator who goes looking for the knob in the env reference does not find it,
and a deployment manifest reviewed against that table cannot be found
incomplete.

**Exploitability.** None. **Likelihood.** Moderate on upgrade.
**Impact.** Operability of a fail-closed security control; at worst a planned
inspected-HTTPS outage at CA expiry instead of a renewal.
**Fix (applied).** Added the row, stating both values, the startup-only
boundary, and that an unset or unrecognised value fails toward *not* renewing.
**CWE.** CWE-1059 (insufficient technical documentation). **OWASP.**
A05:2021 Security Misconfiguration. **Severity.** Low.

---

## Risk Rating

| Finding | Severity | Exploitability | Likelihood | Regression risk | Status |
|---|---|---|---|---|---|
| A — status single-flight ignores configuration generation | Low | None (privileged trigger) | Low today, Medium once a reconfigure caller exists | Medium if left | **Fixed here** |
| B — env var missing from the README reference | Low | None | Moderate on upgrade | Low | **Fixed here** |

**Window verdict: no security regression.** Posture improved on five axes —
trust-anchor ownership (#1854), unauthenticated amplification into the AV
daemon (#1862), admin-UI cleartext downgrade (#1859), a reachable `net/http`
vulnerability (#1864), and CDR capacity visibility (#1858).

---

## Regression Analysis

Change by change, measured against `ac4e223`.

**#1854 — CA provenance.** *Not a regression.*
- Renewal no longer re-keys. The CA private key's lifetime becomes unbounded
  under automatic renewal. Accepted and recorded below (R-1): the alternative
  the window removed did not rotate the key *safely*, it broke every client.
  Re-keying remains available as the manual, documented trust-breaking
  `POST /api/ca/rotate` (`InitCA`).
- Withheld renewal reaches expiry, and expiry is fail-closed —
  `signLeaf` → `caUsable` → error → `GetCertificate` → handshake failure. No
  bypass leg. Verified in source, not from the comment.
- The renewed certificate reuses `RawSubject`; since `parent == template`,
  `x509.CreateCertificate` derives both issuer and subject from it, so name and
  key (and therefore the auto-computed SKI) match the old certificate and a
  single leaf validates under either root. That is the property
  `TestDualCAOverlap_ClientTrustingOnlyOldRootValidates` pins, and
  `internal/ca` passes under `-race`.
- `caChainRaw` is set only when `cert.CheckSignatureFrom(cert)` fails, i.e. for
  an intermediate. A self-signed primary is still withheld from the wire, as
  before; an intermediate is now sent, which is a strict improvement in path
  building and discloses nothing (the client's anchor is its issuer).
- `oldCert` cannot be nil at `oldCert.RawSubject`: `CAExpiry()` returning
  non-zero establishes `caCert != nil`, and no production path assigns nil.
  `SetKeyProvider` has no production caller, so `caKey` cannot be nil either.
- Downgrade-safe: older builds' `ImportBundle` skips unknown PEM block types,
  so a bundle carrying the record still loads on a rollback.
- `apiCAStatus.autoRotation` becomes dynamic (`caAutoRenewed()`); it now reports
  what the node will actually do. Role check unchanged.

**#1862 — CHAOS-116.** *Improvement, one latent defect (finding A).*
- Fail-closed verified on both consumers; failure results cached with the same
  TTL as successes, so the dial rate is request-independent.
- Lock order is consistent (`mu` → `clamProbeMu`); no path takes `mu` while
  holding `clamProbeMu`, and no caller waits on the flight while holding `mu`,
  so the probe can always reach its store. The detached goroutine is wrapped in
  `obs.SafeCall` per the CHAOS-24 contract.
- `PingContext` applies the **earlier** of the caller's deadline and
  `now+timeout`, so it can only tighten `Ping`'s previous bound. A cancelled
  context closes the connection, which is the only way to interrupt a blocking
  `Read`. `Ping()` is preserved as `PingContext(context.Background())`, so no
  existing caller's semantics changed.

**#1861 — catdb single transaction.** *Not a regression.* Key-aliasing argument
verified; `getExact`'s error classification is equivalent to the previous
`db.View` shape, including `ErrDBClosed`-class errors, which still surface
through `Lookup`'s `access` closure to `recordFault`. Per-decision read
consistency improves. The new gate is wired into all three workflows that run
`benchgate` and into the verification workflow's package list, so it is a gate
CI actually runs.

**#1859 — unencodable SANs.** *Not a regression.* The SAN set only narrows;
the log line now reports the set actually certified. IA5 is the only DNS-SAN
constraint `CreateCertificate` enforces.

**#1860 — `MintID`.** *Not a regression.* `mintID` is unchanged; `MintID` only
exposes it without spending a 32-byte key or forcing an id-only caller to carry
an error whose zero value is the **keyless sentinel** `KeyID` reports. On the
pinned toolchain `crypto/rand.Read` cannot return an error (it terminates the
process), so no observable behaviour changed — which the comment states rather
than implying a live guarantee. The three comment corrections in `scanOnce`,
`scan_svc_admission.go` and `traffic_redaction.go` strengthen a real barrier:
anything that reclassified the 429 branch as dead would drop a capacity refusal
into the fault leg, which fails **open**.

**#1858 — CDR capacity row.** *Not a regression.* `cdrCircuitBreaker.State()` is
`b.state.Load()` — a pure atomic read that neither reserves a half-open probe
nor advances the machine, so an admin diagnostics GET cannot consume recovery
budget. `cdrPool` is a non-nil singleton and is the only CDR client path
(single-instance configuration goes through `replace([]*cdrPooledClient{pc})`),
so no configuration escapes the count. The `tripped == 0` case precedes
`tripped >= total`, so an empty pool reports healthy rather than dividing by
zero. Previously-`OK` states now report `Warn`; diagnostics is informational and
gates nothing.

**#1856 — metric rename.** *Not a regression.*
`culvert_scan_svc_at_capacity_total` was introduced by CHAOS-115 in the previous
window and exists only under `[Unreleased]`, so no released operator contract
is broken. The rename is applied consistently across `metrics.go`, the chaos
test, the runbook and the CHANGELOG, and aligns the counter with the existing
`culvert_clam_saturated_total` / `culvert_remote_scan_saturated_total` family.

**#1864 — go1.27.4.** *Improvement.* `go.mod` `toolchain`, the production
builder, the maintenance-agent builder and the e2e builder move together with
digest pins; no workflow `GOTOOLCHAIN` override was introduced.

**#1865, #1857.** Test determinism and documentation governance; no runtime
surface.

---

## Attack Scenarios

Scenarios considered against this window's changes, with the outcome at
`04aa647` + this change:

1. **Unauthenticated scanning suppression** (the CHAOS-116 case). Flood
   `/health` on the proxy port to exhaust the AV daemon's connection queue, so
   real scans fail and content is forwarded unscanned. **Blocked:** one dial per
   flight, at most one per 30 s per process while the daemon answers; no caller
   dials.
2. **Readiness laundering during an AV outage.** Make the node report
   `clamav: ok` while scans fail open. **Blocked:** before any observation,
   `clamStatusUnknown` fails the readiness row; after finding A's fix, a
   superseded observation is discarded rather than published.
3. **Silent downgrade of inspected HTTPS at CA expiry.** Let the CA expire and
   hope the proxy tunnels instead of refusing. **Blocked:** `caUsable` refuses
   the leaf and the error fails the handshake; there is no tunnel fallback on the
   `GetCertificate` path.
4. **Trust-anchor substitution.** Get Culvert to replace an operator's
   enterprise CA with a self-signed one it generated. **Blocked by #1854:** only
   a `culvert-managed` record authorises renewal, the record is never inferred
   from the certificate, and the admin upload path hardcodes `imported`.
   Forging the record requires write access to the bundle, which is already
   write access to the CA private key — no escalation.
5. **Admin plane downgraded to cleartext by a SAN typo.** **Blocked by #1859.**
6. **Log injection through the new surfaces.** `noteCARenewalWithheld` prints
   only `Provenance` constants; the unrecognised-env warning uses `sanitizeLog`
   + `%q`; the probe's transition line uses `obs.Sanitize` + `%q` on both the
   address and the error. **No vector.**
7. **Internal topology disclosure on the unauthenticated surface.** The probe's
   raw value still embeds the daemon's address and port, and
   `clamStatusUnknown` is new free text. **Contained:** `/health` passes every
   value through `coarseClamAVStatus`, and the `/ready` row carries a fixed
   detail. The raw cause stays on the role-gated
   `/api/security-scan/status` and in the support bundle under
   `redact:"internal"`.
8. **Half-open probe budget consumed by an admin page view** (the #1858 case).
   **Blocked:** `State()` is a pure load.

---

## Suggested Fix

Both findings are fixed in this change; no follow-up is required.

- **A.** `internal/secscan/secscan.go`: `clamStatusGen` generation guard across
  `Init`, `startClamStatusProbe` and `runClamStatusProbe`, with ownership-checked
  flight cleanup. Fail-closed on supersession (discard, do not publish).
- **B.** `README.md`: the `CULVERT_CA_PROVENANCE` row.

No security behaviour outside those two points was changed, no validation was
weakened, and no protection was disabled.

---

## Files

Changed by this review:

| File | Change |
|---|---|
| `internal/secscan/secscan.go` | `clamStatusGen` / `clamProbeGen`; `Init` bumps the generation; per-generation single flight; ownership-checked flight cleanup; supersession discard in `runClamStatusProbe` |
| `internal/secscan/clam_status_probe_reconfigure_test.go` | new — four gates for finding A |
| `README.md` | `CULVERT_CA_PROVENANCE` environment row |
| `CHANGELOG.md` | `[Unreleased]` entry |
| `docs/engineering/SECURITY-REGRESSION-REVIEW-2026-11-11.md` | this review |

Reviewed and unchanged (production files in the window): `internal/ca/ca.go`,
`internal/ca/provenance.go`, `rootca_startup.go`, `rootca_startup_config.go`,
`ca_health.go`, `main.go`, `ui_security.go`, `internal/catdb/catdb.go`,
`policy_hostcat.go`, `proxy_host_bounds.go`, `internal/clamav/clamav.go`,
`internal/pseudonym/pseudonym.go`, `internal/secscan/remote.go`,
`scan_svc_admission.go`, `traffic_redaction.go`, `internal/uitls/uitls.go`,
`cdr_pool.go`, `diagnostics.go`, `metrics.go`, `go.mod`, `Dockerfile`,
`test/e2e/maint-agent/Dockerfile.e2e`, the three workflow files.

---

## Required Tests

Added, in `internal/secscan/clam_status_probe_reconfigure_test.go`:

| Test | Kind | Property |
|---|---|---|
| `TestChaos116_ReconfigureDiscardsThePreviousDaemonsObservation` | regression, negative | After `Init` repoints to an unreachable daemon, the previous daemon's `connected` answer is never published, and the newly configured address *is* probed |
| `TestChaos116_SupersededProbeDoesNotClearTheCurrentFlight` | boundary | A superseded probe finishing after a new flight starts must not clear the new flight's handle (otherwise the next caller opens a second dial) |
| `TestChaos116_SameGenerationReadersStillShareOneProbe` | positive, negative control | Without a reconfigure, 32 concurrent readers still produce exactly one dial — the generation must not split the flight CHAOS-116 exists to merge |
| `TestChaos116_ReconfigureUnderConcurrentReadersNeverPublishesStaleHealth` | concurrency (`-race`) | With 16 readers hammering the surface across the reconfigure, no read ever returns `connected` for the unreachable daemon |

The gates were verified to **fail without the fix**, with the guards neutered in
place and the field kept so the package still compiles: the three
reconfigure-sensitive tests fail by name (two of them through a bounded wait
that reports *why*, so a future regression fails cleanly instead of hanging the
package to its timeout — the unguarded behaviour is a deadlock, since the
warm-up joins a flight the test holds open), while the negative control passes.
Each gated fake is released through an idempotent `t.Cleanup` so a failing test
does not leak its probe goroutine.

Authentication and authorization tests were **not** added, and should not be:
nothing in this change touches an authenticated surface. `Scanner.Init` is
startup wiring, and the probe is internal to the scanner.

### Checks run at this SHA

```sh
go build ./...                                         # clean
go test -race -count=1 ./internal/ca ./internal/catdb ./internal/clamav \
    ./internal/secscan ./internal/pseudonym ./internal/uitls             # all ok
go test -race -shuffle=on -count=2 ./internal/secscan                    # ok
go test -count=1 -run 'TestRootCA|TestProvenance|TestChaos116_|TestDiagnosticsCDR|TestCDRCapacity|TestReadyz|TestCoarseClam' .   # ok
go test -tags benchgate -run 'TestBenchGate_' -count=1 -p 1 ./internal/catdb ./internal/secscan   # ok
golangci-lint run ./internal/secscan/...               # v2.15.0 (the Fast PR Gate's pin): 0 issues
python3 docs/agent-context/check.py                    # ok
```

**Not run, and why.** `govulncheck` v1.5.0 could not fetch
`https://vuln.go.dev/index/modules.json.gz` — the environment's egress policy
returns `Forbidden`, so the Fast PR Gate's vulnerability job is unverified here;
#1864's claim about GO-2026-6859 was taken from the Go release the toolchain
line pins, not executed. The full root-module suite, the race/shuffle
aggregates, CodeQL and the hosted gates were not run locally. A passing local
check is not a passing hosted review or merge gate.

---

## Residual Risk

Carried forward and newly recorded. None is a regression introduced by a change
this review approved without saying so.

- **R-1 (new, accepted).** The inspection CA's **private key** now has an
  unbounded lifetime under automatic renewal: renewal re-issues the certificate
  for the same key. A key compromise therefore survives every automatic
  renewal. Re-keying is the manual `POST /api/ca/rotate`, which is trust-breaking
  by design and documented as such. This is the correct trade — the behaviour it
  replaced broke inspection for every client on every rotation — but a
  key-rotation procedure with a distribution window, rather than a break-glass,
  does not yet exist.
- **R-2 (new, accepted).** `CULVERT_CA_PROVENANCE` is a **single global
  assertion** applied to any record-less bundle, including one that arrives
  later by restore (`restore.go:650` → `ImportBundle`). An install whose
  record-less bundles are of mixed provenance across restores can therefore
  classify an imported CA as managed and have it renewed as self-signed. The
  operator made the assertion explicitly, the safe default is unknown ⇒ never
  renew, and a recorded provenance always wins — but the knob cannot distinguish
  two record-less bundles.
- **R-3.** The classification is in memory until the next `SaveCA`. Until then,
  removing the env var silently returns the CA to "never renewed" — announced by
  the startup log line and the 24-hourly alert, but not by any gate.
- **R-4.** The `cert_expiry` alert for withheld renewal fires only when
  `globalAlertStore.HasSubscriber("cert_expiry")`. Without a subscriber the only
  signals are the log line, the pre-existing `ca_expires_days` health field and
  the `sslInspection: expired` row. Unchanged by this window.
- **R-5.** A ClamAV store/daemon fault still forwards content **unscanned**
  (`statClamScanError`, fail-open), and a `catdb` store fault still answers
  "uncategorized" on the policy data path. Both are pre-existing, deliberate and
  out of scope here; #1862 and #1861 narrowed their blast radius without
  changing the posture.
- **R-6.** `checkCDRCapacity`'s `tripped >= total` message says all instances
  "are being probed for recovery", and its code comment says "open-past-timeout
  or half-open". `State()` also reports plain `cbStateOpen` *inside* its
  timeout, when nothing is being probed yet. Operator-facing wording only; the
  recommended action is correct in every case. Not changed here to keep this
  review's diff to its findings.
