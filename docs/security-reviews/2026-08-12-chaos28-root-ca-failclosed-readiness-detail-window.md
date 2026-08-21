# Security Regression Review — CHAOS-28 Root-CA fail-closed, alert-rename ingress completion, release version identity, async-syslog panic observer (window `1c24311` → `bc67b7b`)

> **Reviewer role:** Security Regression Engineer (AppSec / Secure Code Review / Product Security)
> **Review date:** 2026-08-12
> **Baseline:** `1c24311` — head of the previous review's window
> (`docs/security-reviews/2026-08-09-alert-rename-ingress-hostutil-fastpath-dedup-bound-window.md`)
> **Head:** `bc67b7b` (`main`)
> **Scope reviewed:** every code-bearing change in the window — 13 first-parent
> merges (PRs #1083–#1103), 57 files, +4,517 / −113.
>
> **Method.** Prioritised by *live blast radius*, not diff size:
>
> 1. **The TLS-inspection trust root** — CHAOS-28 is the largest change in the
>    window and it moves the appliance's primary security control from
>    fail-silent to fail-closed. A mistake here is either a fleet-wide bypass of
>    DLP/AV/YARA/CDR/DPI or a fleet-wide outage, so the guard, its dispatch
>    site, and every surface it feeds were reviewed adversarially rather than
>    diffed.
> 2. **Unauthenticated network surfaces that changed** — `/healthz`, `/health`
>    and `/ready` all gained or changed fields. These are reachable without
>    credentials, `/health` and `/ready` on the **proxy** port that every client
>    on the network already dials, so anything written there is public.
> 3. **The alert plane** — completion of the `idp_unreachable` →
>    `identity_backend_unreachable` migration (the previous window's finding
>    SR-2026-08-09-01), re-reviewed for *detection loss* rather than
>    enforcement.
> 4. **Release/supply-chain integrity** — the new release-identity guards, since
>    a gate that fails as a configuration error is indistinguishable from a gate
>    that passed.
> 5. **Privileged host surface** — the `allow_peers` installer patcher, which
>    decides which local UID may drive the maintenance agent.
>
> Dependency bumps (`kin-openapi` 0.146.0, `klauspost/compress` 1.19.2,
> `badger/v4` 4.9.6) and GitHub Action pin bumps were confirmed to be
> **SHA-pinned** with the comment tag matching the moved SHA; no action moved to
> a floating ref.

---

## Executive Summary

**One finding, fixed in this change:**

- **SR-2026-08-12-01 (MEDIUM, information disclosure / security-posture
  oracle)** — the **unauthenticated** `/ready` probe on the **proxy listener**
  answered two of its rows with raw internal error strings. Together they
  published the CA bundle's absolute filesystem path, the internal address and
  port of the ClamAV daemon, and an explicit, machine-readable statement that
  the gateway's inspection controls are currently off
  (`SSL inspection DISABLED (TLS traffic is tunnel-only: no scanning/DLP/CDR)`).
  Any user on the network could poll it to learn precisely when DLP, AV, CDR
  and DPI are down, and time exfiltration to that window.

**This window's headline change — CHAOS-28 Root-CA fail-closed — is a
significant net security improvement and is correctly implemented.** It closes
a genuine silent-fail-open class: `x509.CreateCertificate` does not check the
issuer's validity window, so an expired inspection CA kept minting well-formed
leaves that every client rejects, with `/healthz` reporting
`ssl_inspection: ready` throughout. Three properties were specifically verified
and hold:

- The refusal **does not** fall through to the bypass branch, so an
  appliance-wide CA fault cannot silently disable inspection fleet-wide.
- The refusal **does not** honour a decryption profile's `OnInspectError=fail-open`,
  so a host-independent fault cannot poison the per-origin auto-exclusion cache.
- The refusal **does not** feed the auto-exclusion learner at all.

Beyond the one finding there is **no authentication bypass, no authorization
bypass, no default-allow, no missing deny, no policy-precedence change, no
weakened certificate validation, no missing signature validation, no new SSRF,
open-redirect, injection or traversal primitive, and no secret exposure.**

Three changes deserve explicit *clearance* rather than silence, because each is
the kind of change that usually costs security and here does not:

- **The cert-cache `cacheOrder` de-duplication is behaviour-preserving**, not
  merely "close enough" — eviction was already governed by the first insertion
  (later duplicates always resolved to "already gone" and were skipped), so
  removing them changes no eviction decision while fixing an uptime-scaled
  unbounded-slice leak.
- **`logClockStamp`'s memoisation is exact, not approximate** — the layout has
  one-second resolution and the cache is keyed on `(unix second, *time.Location)`,
  so a hit returns byte-identical output. The location key removes the
  UTC-served-a-Local-render misuse class outright.
- **Gating the CA rotation-success signal on persistence fails toward *more*
  operator warning, never less** — the correct and only acceptable direction.

---

## Security Findings

### SR-2026-08-12-01 — the unauthenticated readiness probe published the CA bundle path, the AV daemon's internal address, and an explicit "security controls are off" signal

| | |
|---|---|
| **Severity** | **MEDIUM** (HIGH for a deployment where the proxy port is reachable by untrusted or BYOD clients) |
| **CWE** | CWE-209 (Generation of Error Message Containing Sensitive Information); with CWE-200 (Exposure of Sensitive Information) and CWE-497 (Exposure of System Data to an Unauthorized Control Sphere) |
| **OWASP** | A01:2021 Broken Access Control (unauthenticated read of operator-only diagnostics); A05:2021 Security Misconfiguration |
| **Status** | **Fixed in this change** |
| **Regression risk of the fix** | **None to the verdict** — status codes, row presence and gating are byte-identical; only the human-readable `detail` string changes |

#### What the code did

`/ready` is dispatched by `routeProxyListenerBuiltin` (`pac.go:126`) on the
**proxy listener** — the port every client already dials to use the gateway.
It has no authentication and no IP guard. Two rows passed raw internal errors
straight into the response body:

```go
// healthcheck.go — before
checks["ca"] = &readinessCheck{Status: "fail", Detail: sslInspectionLoadFailure()}
...
checks["clamav"] = &readinessCheck{Status: "fail", Detail: st}
```

`sslInspectionLoadFailure()` is built by `noteSSLInspectionUnavailable`
(`rootca_startup.go:31`) as
`"Root CA load/init failed for <path>: <OS error> — SSL inspection DISABLED (TLS traffic is tunnel-only: no scanning/DLP/CDR)"`,
and `ClamAVStatus()` returns `fmt.Sprintf("unreachable: %v", err)`
(`internal/secscan/secscan.go:303`) — a raw dial error carrying the daemon's
address.

#### Proof (observed, not inferred)

Both were reproduced against the real binary built from `bc67b7b`, probed
unauthenticated over plain HTTP on the proxy port:

```
$ curl -s http://127.0.0.1:18080/ready
{"status":"ready", ... "checks":{"ca":{"status":"fail","detail":
 "Root CA load/init failed for /…/nodir/sub/ca.bundle: CA save: CA write:
  atomic write /…/nodir/sub/ca.bundle: create temp: open
  /…/nodir/sub/ca.bundle.tmp.3590368959: no such file or directory
  — SSL inspection DISABLED (TLS traffic is tunnel-only: no scanning/DLP/CDR)"}, …}}

$ curl -s http://127.0.0.1:18086/ready
{… "clamav":{"status":"fail","detail":
 "unreachable: clamav: connect failed: dial tcp 127.0.0.1:1: connect: connection refused"} …}
```

#### Attack scenario

1. An insider, a compromised endpoint, or malware on any workstation that is
   configured to use the gateway polls `http://<proxy>:<port>/ready` on a timer.
   No credentials, no admin port, no privileged position — this is the same
   socket the host already uses for normal browsing.
2. The `ca` row tells it, in machine-readable form, the exact moment SSL
   inspection is disabled — i.e. when DLP, AV, YARA, CDR and DPI are **not**
   examining TLS traffic, because the string says so in those words.
3. The `clamav` row independently reports when malware scanning is down, and
   discloses the internal address and port of the AV daemon — a lateral-movement
   target that is otherwise not visible from a client subnet.
4. The attacker times exfiltration or malware retrieval to that window. Because
   the gateway is failing *open* to tunnel-only in the CA case, the traffic is
   relayed but never inspected, and the operator's own logs will show it as an
   ordinary CONNECT.

The CA bundle path is a secondary benefit to the attacker: it names the exact
file to target for a denial-of-inspection attack (make the bundle unreadable and
inspection stays off), and confirms the container/host layout.

#### Preconditions, exploitability, likelihood

- **Preconditions:** network reach to the proxy port — i.e. any user of the
  gateway. No credentials, no session, no admin-port access.
- **Exploitability:** trivial. One unauthenticated HTTP GET; no parsing beyond a
  substring match; fully scriptable.
- **Likelihood:** the *disclosure* is certain whenever either dependency is
  degraded (a wrong `CULVERT_CA_PASSPHRASE`, an unwritable data volume, or a
  ClamAV restart are all routine). Weaponising it requires an attacker already
  inside the client population, which is precisely the threat model a Secure Web
  Gateway exists to address.
- **Impact:** loss of confidentiality of internal topology and operator-only
  diagnostics, plus a reliable oracle for when the appliance's security controls
  are not enforcing. It does not by itself bypass a control; it tells an attacker
  when the controls are already bypassed.
- **Affected assets:** the Root CA bundle path, the ClamAV daemon's internal
  address/port, and the confidentiality of the gateway's real-time enforcement
  posture.

#### Why this is in scope for a regression review

The defect predates this window (it arrived with CHAOS-06). It is reported here
because **this window is where the contract that forbids it was written**. The
CHAOS-28 branch added directly beneath the offending line states the rule
explicitly:

> The detail is a FIXED string. `/ready` is served unauthenticated on the proxy
> port … an unauthenticated "this gateway's inspection CA expired at T" is a
> fingerprint of a security-degraded node.

The new code applied that guardrail to its own branch and left the adjacent
branch — on the same row, in the same `switch`, three lines above — publishing a
strictly larger amount of the same class of information. A rule that holds for
one branch of a row and not its sibling is not yet a control, and the sweep test
added below is what makes it one.

#### Fix applied

Both details are now fixed, operator-directed strings, matching the pattern the
same function already uses for the quarantined-state-file and expired-CA rows:

```go
// healthcheck.go — after
checks["ca"] = &readinessCheck{
    Status: "fail",
    Detail: "configured root CA is unavailable — see server logs",
}
...
checks["clamav"] = &readinessCheck{
    Status: "fail",
    Detail: "ClamAV unreachable — see Security Scanning status in the admin UI",
}
```

Two details of that wording were corrected in review (Codex, PR #1122) and are
worth recording, because both are mistakes the obvious fix invites:

1. **The redaction must drop the enforcement POSTURE, not just the cause.** The
   first cut read `"configured root CA failed to load; SSL inspection is
   disabled — see server logs"`. That removes the path and the OS error but
   *keeps the exfiltration oracle* — the sentence still tells an unauthenticated
   observer that inspection is off right now, which is the whole prize. The
   distinction that matters is between the row and the posture: `ca: fail` says a
   named subsystem is degraded and does not say **which way** it fails, and the
   two directions are opposite — a load failure degrades to tunnel-only
   **bypass** (traffic flows uninspected, an attacker's window), whereas the
   CHAOS-28 validity branch fails **closed** (traffic refused, no window). Naming
   the posture is only hazardous in the first case, which is exactly the branch
   that was doing it.
2. **"See server logs" has to be true of the *runtime* condition.** It is, for
   the `ca` row: `sslInspectionLoadError` is written only by
   `noteSSLInspectionUnavailable` from `loadRootCA`, so the condition is
   startup-scoped and the startup log records it. It is **not** true for ClamAV:
   `Scanner.Init` logs the ping error at startup and reconfigure only, while
   `ClamAVStatus` caches it and logs nothing — so a daemon that dies at runtime
   (restart, OOM, crashed container — the ordinary case) yields a failing row
   with no matching log line. That row therefore points at the role-gated
   `/api/security-scan/status`, which re-pings on cache miss and always carries
   the live cause.

**Nothing is lost to the operator.** The full CA cause remains in the process
log and in the `ca_load_failed` alert payload; the full ClamAV status remains on
the role-gated `/api/security-scan/status` (`clamav_status`). Both were verified
present after the fix.

**Nothing changes about the verdict.** The `ca` row still reports `fail` and
remains report-only; the `clamav` row still reports `fail` **and still gates
readiness to 503**. This is asserted explicitly by a dedicated test, because
trading an information leak for a monitoring regression — a load balancer
happily routing to a node with no malware scanning — would be a worse outcome
than the leak.

Verified live after the fix:

```
{"status":"not_ready","checks":{
  "ca":{"status":"fail","detail":"configured root CA failed to load; SSL inspection is disabled — see server logs"},
  "clamav":{"status":"fail","detail":"ClamAV unreachable — see server logs"}, …}}
```

#### Files

- `healthcheck.go` — `appendCAReadinessCheck` load-failure branch; `computeReadiness` ClamAV branch.
- `readyz_detail_disclosure_test.go` — **new**, the regression suite.
- `rootca_failure_visibility_test.go` — `TestHandleReady_SurfacesCALoadFailure` updated: it previously *pinned the vulnerable behaviour* by asserting the raw cause appeared in the detail. It now asserts the fixed string **and** the absence of the path and cause, so the CHAOS-06 visibility guarantee (the failing row) and the disclosure guardrail are pinned together.

#### Required tests — all added and passing

| Test | Class | What it pins |
|---|---|---|
| `TestReadyz_CADetailWithholdsPathAndCause` | Negative / malformed-input | The real producer's verbatim string is stored, and the response must contain neither the bundle path, the OS cause, nor any enforcement-posture wording. Matching is **case-insensitive**: the first cut compared against the producer's exact capitalisation (`SSL inspection DISABLED`) and therefore passed vacuously against its own replacement (`SSL inspection is disabled`) — the test was strengthened and confirmed to fail against that string before being accepted |
| `TestReadyz_ClamAVDetailWithholdsDaemonAddress` | Negative | Daemon host, port, and dial-error text absent; **and** the row points at the admin surface rather than the log, since a runtime ClamAV outage is never logged |
| `TestReadyz_ClamAVFailureStillGates` | Positive / boundary | Redaction did not weaken the verdict — an unreachable AV daemon still returns 503 |
| `TestReadyz_NoDetailCarriesRawInternals` | Regression sweep | **Every** row present in the process, not just the two fixed, is checked for raw-error markers (`dial tcp`, `connect: `, `permission denied`, absolute paths) — so a row added later cannot quietly reintroduce the class |
| `TestHandleReady_SurfacesCALoadFailure` (updated) | Positive + negative | The failing row is still present and still report-only, with a redacted detail |

Concurrency and authorization coverage are inherited rather than duplicated: the
endpoint is unauthenticated by design (there is no role to test), and the two
sources it reads are an `atomic.Value` and a mutex-guarded cached status, both
already exercised under `-race`. The suite was run with
`-race -count=2 -shuffle=on` and is clean.

#### Residual risk

- **The row's *existence* is still an oracle.** `status: "fail"` on the `ca` or
  `clamav` row still tells an unauthenticated observer that a dependency is
  degraded, without saying which way. This is deliberate and is the CHAOS-06
  visibility contract — a readiness probe that hides failure is not a readiness
  probe. Deployments that consider even that too much should not expose the
  proxy port's built-in endpoints to the client population; that is a network
  placement decision, not a code one.
- **`/health` on the same unauthenticated port still reports `version`,
  `ca_expires_days` and `ssl_inspection: load_failed|unavailable|expired`.**
  These are bounded, fixed-vocabulary tokens rather than raw internals, and they
  long predate this window, so they are recorded as accepted posture rather than
  changed here. Note that `ca_expires_days` already lets an unauthenticated
  observer compute CA expiry, which is why the CHAOS-28 authors' concern about
  the expiry timestamp is best read as being about *precision and phrasing*
  rather than a novel disclosure.

---

## Observations (no change made)

Neither of these is a regression; both are recorded so the next reviewer does
not have to re-derive them.

### OBS-1 — `/api/ca/status` returns `rotationPersistError` to the **viewer** role

`ui_security.go` now surfaces `unusableReason` and `rotationPersistError` on
`/api/ca/status`, which is `MinRole: RoleViewer`. The `checkRootCA` comment in
`diagnostics.go` states the intent as "full detail stays in the logs, the alert,
and the **admin-role** CA API" — but that API is viewer-role, and
`rotationPersistError` is an OS error that will normally contain the CA bundle's
filesystem path.

Impact is low: a viewer is an authenticated administrative principal, and
`unusableReason` adds nothing the same response does not already disclose
(`expiresIn` and `CACertInfo()` already carry the CA's validity). Only the
persist error introduces a new information class. **Not changed here** — the
GUI's CA panel reads the field for all roles, so narrowing it is a deliberate
product decision rather than a regression fix. Recommended direction if it is
taken up: keep the boolean `rotationPersistDegraded` at viewer, and gate the
`rotationPersistError` string on admin.

### OBS-2 — `caUsabilityDegraded()` and `caInspectionUsable()` are effectively dead

Their doc comments claim they are "used by the operator contract, `/healthz`,
`/readyz` and `/metrics`" and that `caInspectionUsable` is "the single live
predicate", but every one of those surfaces calls `certMgr.Usable()` directly;
only tests call these two. This is **not** a security defect — the live call is
if anything the more honest answer, and it clears immediately on rotation rather
than waiting for latched-state evidence. It is recorded because the comments
would mislead a maintainer into wiring the latched predicate into a surface that
currently reports live truth. The one real consequence is that recovery evidence
(`noteCAUsable`) is contributed **only** by a successful inspected CONNECT
(`proxy_tunnel.go:343`), which is the correct source anyway.

---

## Regression Analysis — cleared changes

Each of these was reviewed against the specific way it could have weakened
posture, and cleared.

### CHAOS-28 Root-CA fail-closed (`internal/ca/validity.go`, `ca.go`, `ca_health.go`, `proxy_tunnel.go`)

| Risk considered | Finding |
|---|---|
| Does the guard convert an availability fault into a **bypass**? | **No.** `failClosedUnusableCA` returns 502 *before* the 200 and `return`s; it never reaches `handleTunnelBypass`. Pinned by `TestHandleTunnel_ExpiredCAFailsClosedNotBypass`. |
| Does it honour `OnInspectError=fail-open`? | **No**, deliberately. Verified by reading the dispatch site: the profile is not consulted. Correct — the fail-open contract is scoped to per-origin incompatibility behind a confirm-count; an appliance-wide fault would poison the whole auto-exclusion cache. |
| Does it feed the auto-exclusion learner? | **No.** `caUnusableOutcome` sets no learner fields. |
| Is `Ready()` still distinct from `Usable()`? | **Yes**, and this is load-bearing. Folding validity into `Ready()` would route the fault into the `inspect_unavailable` *bypass* branch — the exact inversion the guard exists to prevent. |
| Can an already-expired CA still auto-rotate (the only recovery path)? | **Yes.** `RotateIfNeeded` gates on `time.Until(expiry) > caRotationOverlap`; for an expired CA that value is negative, so rotation proceeds. The stale CA is installed as secondary with its original (past) expiry, so `secondaryActive` is false and it is correctly **not** added to the served chain. |
| Is the skew tolerance applied in the safe direction? | **Yes.** Expiry is strict (`now.After(NotAfter)`, no grace); only `NotBefore` gets the 5-minute tolerance, matching the leaf backdating. |
| Can a leaf outlive its issuer? | **No** — `clampLeafValidity` clamps both bounds, and the guard above it makes the clamped window provably non-empty. |
| Are all inspection entry points covered? | **Yes.** `handleTunnelInspect` has exactly one caller (the guarded dispatch), and both `GetCertificate` closures (`proxy_tunnel.go:572`, `proxy_tunnel_h2.go:297`) reach `signLeaf`, which carries the same guard as defence-in-depth. SOCKS5 does not inspect. |
| Is the alert producer gated per the per-request contract? | **Yes** — `fireCAUnusableAlert` checks `HasSubscriber` *before* spawning, and the observer is itself panic-contained. |
| Could the health-plane observer recurse? | **No** — the CA observers do memory-only work plus a gated log/alert; they never re-enter the sign path. |

### Alert event-name migration completion (`internal/alerts/store.go`)

Closes the previous window's SR-2026-08-09-01. `normalizeEventNames` is now
applied at all three ingresses (`Init`, `Add`, `Update`), which covers
`POST /api/config/import` and operator automation, not just disk load. The
mapping is **one-way and closed** — it can only carry a subscription forward to
the same event under its current name, and it never adds or removes an event —
so it cannot widen or narrow what a webhook receives. Duplicate collapse is
order-preserving and display-only (`Dispatch` already stops at the first match).
Cleared.

### `apiSyslogConfig` panics/drops read ordering (`ui_config.go`)

The read order (`Panics()` **then** `Drops()`) is correct and the comment's
reasoning holds: the writer increments panics-then-drops, so reading in the same
order means an observed `panics > 0` implies the later-read `drops` is at least
as large. The UI gates the panic message on `drops > 0`, so this ordering is the
one that cannot hide a real panic behind a stale `drops == 0`. The reverse order
could. Cleared.

### Release version identity (`ci.yml`, `.github/scripts/*`, `ha.go`)

- Both new guards use **env indirection** (`REF_NAME: ${{ github.ref_name }}`
  then `"$REF_NAME"`), never interpolating a ref into `run:` text — no script
  injection.
- `assert-release-ref.sh` is fail-closed and anchored (`^v[0-9]+\.[0-9]+\.[0-9]+$`),
  refusing empty, `dev`, `latest` and SHA identities on **both** the release and
  the reproducible-build paths, so the two cannot drift on the version stamp.
- `assert-runtime-version.sh` runs **after** the build and **before** cosign, so
  it gates the actual bytes under signature.
- Adding `version` to `/healthz` is consistent with pre-existing posture:
  `/health` on the proxy port already returned `version` unauthenticated.

### `allow_peers` installer patcher (`scripts/install.sh`)

The quote-aware `find_comment_start` is a correctness fix on a privileged
surface (which local UID may drive the maintenance agent). Both directions were
checked: the previous behaviour with a trailing comment mis-classified the line
as a multi-line array and **failed closed** (`exit 42`, install aborts), and the
old whole-line UID match could false-positive on a comment mentioning the UID —
also failing closed (peer never added, agent rejects). The new code cannot add a
UID the caller did not supply; `uid` is still validated numeric and non-zero at
the top of the function, and the result is installed `0640 root:culvert-maint`.
The unhandled `\"`-escape case is documented and out of scope for usernames.
Cleared.

### Performance changes on the request path

- **`logClockStamp`** — exact, keyed on `(unix second, *time.Location)`, and the
  only failure mode of a lost race is two goroutines computing the identical
  string. `persistLogEntry` now takes **one** clock read for both `TS` and
  `Time`, which additionally removes a real (if cosmetic) defect: two reads could
  straddle a second boundary and emit disagreeing fields.
- **`cacheOrder` de-duplication** — behaviour-preserving, as argued above; the
  eviction loop still skips entries no longer in the map, so the invariant it
  relies on is unchanged.

---

## Risk Rating

| ID | Severity | Regression risk | Status |
|---|---|---|---|
| SR-2026-08-12-01 — unauthenticated `/ready` disclosed CA path, AV daemon address, and enforcement posture | **MEDIUM** (HIGH where the proxy port serves untrusted clients) | **None** — verdict, status codes and gating unchanged | **Fixed** |
| OBS-1 — `rotationPersistError` at viewer role | Informational | n/a | Recorded, not changed |
| OBS-2 — dead usability predicates with misleading comments | Informational | n/a | Recorded, not changed |

---

## Residual Risk (window-level)

1. **The proxy listener's built-in endpoints remain unauthenticated by design.**
   `/health`, `/ready`, `/metrics` and the PAC paths are all served to any client
   that can reach the proxy port. `/metrics` is token-gated; the other two are
   not. This is a deliberate product contract (load-balancer and client
   probing), and the fix above brings their *content* in line with it, but the
   surface itself is a network-placement decision.
2. **CHAOS-28 trades availability for enforcement, on purpose.** An expired Root
   CA now refuses every inspect-matched CONNECT with 502 instead of emitting
   leaves that fail client-side anyway. Traffic that was already broken stays
   broken; what changes is that the appliance now says so. Operators who have
   not configured the `cert_expiry` alert or scraped
   `culvert_ca_expires_in_seconds` will meet this as a hard failure rather than
   a warning — the runbook (`docs/operator/root-ca-expiry.md`) is the
   mitigation.
3. **`caUsabilityDegraded()`'s recovery evidence comes only from live inspected
   traffic.** A node that recovers but receives no inspect-matched CONNECT keeps
   the latched flag set. No user-visible surface reads it today (OBS-2), so the
   effect is nil, but it would matter if a future change wired it in.
4. **The per-pattern ReDoS timeout harness still exists in `internal/yara`**
   (`matchRegexWithTimeout`), as recorded in `CLAUDE.md`. Unchanged this window;
   still deferred.

---

## Verification performed

- `go build ./...` — clean.
- `go vet ./...` — clean.
- `go test ./...` — **101 packages, exit 0**, no failures.
- `go test -race -count=2 -shuffle=on` over the CA, health and readiness tests —
  clean (the project's determinism-gate profile).
- `gofmt -l` — clean on all touched files.
- Live black-box probe of the built binary before and after the fix, on the
  unauthenticated proxy port, for both the `ca` and `clamav` rows.
- Confirmed post-fix that the full cause is still present in the process log and
  on the role-gated `/api/security-scan/status`.

> `golangci-lint` could not be run locally: the installed binary is built
> against Go 1.25 and panics on this Go 1.26 module. CI's pinned version covers
> it; `gofmt` and `go vet` are clean.
