# Security Regression Review — 2026-11-22

**Scope.** `491b9630…155df09` — the window since the 2026-11-19 review: 54
merged pull requests (#1955–#2008), 101 non-merge commits, 313 files,
+38,867/−4,288. Reviewed at `155df0944b6c1c384c541db89a0293bd201ebc0e`, which
is also `origin/main`.

**Question asked.** Not "is the change good?" but the inverse: **did it weaken
the posture that existed at `491b9630`?** Every verdict is measured against
that revision. Where a finding is in NEW code with no base equivalent, or
pre-existing rather than newly introduced, it says so.

**Headline.** No enforcement regression. Nothing in this window lets a request
bypass policy, a session survive revocation, a feed record be accepted without
a valid signature, a certificate validity bound be loosened, a file land with
looser permissions, or an admin route be reached below its role. The window's
largest changes are nine package extractions (IM-015…IM-028) that are
behaviour-preserving — four of them verified byte-identical here — plus two
genuine hardening rounds (CHAOS-125's inspection setup window, CHAOS-126's OTLP
span accounting, which closed a real cross-destination telemetry leak).

Every finding is in the **observability and audit plane**, and three of the five
share one root cause: *a flag that means "a page was delivered" was also used to
mean "this episode happened".* The 2026-11-19 review's own fix
(SEC-TFEED/BLFEED-STALE-LATCH-1) correctly made the paging latch consume an
episode only on delivery — and in doing so silently disarmed the
episode-ended log line on every node in the default posture, which is the node
that pages nobody and therefore depends on the log. All five findings are fixed
here, each proven by reverting the fix and watching the new gate fail.

| Change | Security surface |
|---|---|
| `boundLoginRelay` (auth) | An anonymous client can no longer park ~1 GiB per interactive-login state store. Validation at both callbacks is unchanged; the bound can only narrow a relay, never widen it. **Hardening** |
| `socks5GuardAndDial` + `socks5_hangup.go` | The SOCKS5 connect phase is cancellable, releasing a goroutine, a descriptor and a connlimiter slot ~20 s early. **Hardening — and the source of Finding A** |
| `armInspectSetupDeadline` (CHAOS-125) | A hijacked inspect leg carries an absolute 30 s setup deadline where it previously carried none. Every new outcome is a teardown. **Hardening** |
| `readNativeClientOffer` (h2) | A client that stalls mid-ClientHello is refused instead of being silently degraded to `http/1.1`. **Hardening — an inspect rule can no longer be downgraded by a client stall** |
| `SpanExporter.push` (CHAOS-126) | The destination and the batch are now taken under one lock hold. Spans recorded for collector B were being POSTed to collector A with A's headers on every repoint. **Closes a real telemetry data leak** |
| `deliveryErrText` / `URLOrigin` (alerts) | A webhook URL is a bearer credential; it is out of the delivery history, the process log and the viewer-readable listing. **Hardening — and the sibling the update arm's audit never got (Finding D)** |
| `MaxWebhooks` + `importAlertWebhooksRejected` | Both write ingresses now cap the webhook count and validate URL/event shape; the import ingress previously validated neither. **Hardening (CWE-770)** |
| `openLogAppend` (fileutil) | The rotating log open gained `O_NOFOLLOW` + `O_NONBLOCK` + an `IsRegular` check. **Hardening (CWE-59/61)** |
| `env_put` umask / `set -C` (install.sh) | The installer's secret file is created private from the start instead of narrowed afterwards. **Hardening (CWE-367)** |
| `ensureCDRHealthPoller` | A runtime CDR enable now arms certificate auto-renewal, pin rotation and pool re-dial without a restart. **Availability of a security control** |
| `latchOncePerEpisodeOnDelivery` | Paging is correct; the episode-ended log line it also gated is not. **Source of Findings B and C** |
| `retireSupersededRecords` (maint) | A later image change retires every other interrupted journal record, including a data rollback's. **New control — and the source of Finding E** |
| `clamav_signature_freshness.go` | A stale ClamAV definition set now has a WARN row, gauges and an alert. **New detection for a scan control** |
| `internal/frontendbundle`, `hostpin`, `revsync`, `qualinventory`, `livetier`, `clusterca`, `noderecord`, `writerlock`, `listenfault` | Package extractions. **Behaviour-preserving** |

**Method.** Four independent investigations ran in parallel over the proxy data
path, the admin control plane and diagnostics, feed trust and crypto, and
persistence/lifecycle/the maintenance agent. The interactive-login bound, the
frontend-bundle extraction, the revocation-sync planner, the host-pin predicate,
the live-tier state machine, the qualification-inventory validators, the OTLP
push path, the SOCKS5 hangup watcher, the installer scripts and the legacy UI
diff were reviewed directly. **Every finding below was re-derived from source by
the reviewer against `git show 491b9630:<path>` — no finding rests on a worker
summary** — and all five fixes are proven differentially.

---

## No regression found in

- **The nine package extractions.** Four were verified byte-identical after
  normalising names: `internal/hostpin` (the inner-host pin predicate, diff
  exit 0), `internal/session/revsync` (the revocation budget planner, including
  the rotating window that keeps a deferred revocation propagating),
  `internal/frontendbundle` (the asset-path trust boundary — same traversal,
  encoding, namespace and sourcemap rules, same hash regexp, same MIME
  allowlist converted from a map to an equivalent switch), and
  `qualinventory`'s `validateOpaqueField` / `validateRouteSafeSegment`. The
  `livetier` state machine is identical transition-for-transition, with the
  three injected seams (`SetArmed`, `DepsReady`, `CommitLock`) wired to the same
  values root used inline and defaulting fail-closed (`DepsReady` → `false`)
  when nil. `clusterca`, `noderecord`, `writerlock` and `listenfault` were each
  cleared boundary-condition by boundary-condition by the owning investigation,
  with the project's own differential oracles (a >20,000-input differential and
  a 786k-exec fuzz run against a frozen copy of the old decoder) re-run at head.
- **Signature and provenance verification.** The entire `internal/urlcatfeed/verify.go`
  diff is two identifier exports; the Sigstore body, the 8 call sites and the
  strict-JSON gates (`scanStrict`, `requireCanonical`) are untouched. The
  generation/floor rollback machinery — `selectFloor`, `detectEquivocation`,
  `checkAdvanceAllowed`, `verifyReadBack` — is unchanged in this window.
- **Cluster CA validity.** `now.After(NotAfter)` and the strict
  `now.Before(NotBefore)` (deliberately **no** skew tolerance, unlike
  `caClockSkewTolerance`) survive the extraction unchanged, as does
  `errClusterCAUnusable` as the *same error value*, so every `errors.Is` caller
  is unaffected. The package imports no `time.Now`, enforced by a boundary test.
- **RBAC and route surface.** No route-registration file, no `ui_rbac.go` and no
  `MinRole` changed in this window. Every handler the diff touched keeps its
  handler-level `requireRole`. The two new diagnostics rows emit **counts only**,
  and the data they summarise is already viewer-readable at finer grain through
  `GET /api/cdr/instances` and `GET /api/policy`; no private key is read.
- **The scan admission gate.** `internal/secscan/sidecargate` is a faithful move:
  `Acquire` still returns `(nil, false)` on timeout and the handler still
  answers **429** before reading any body, which the caller classifies as
  `remoteOutcomeCapacity` and fails **closed**. `Slots(window)`'s `window <= 0`
  arm is unreachable in production — `scanSvcWindow()` floors at 5 MiB.
- **The SOCKS5 destination-policy chain.** Parsing, `normalizeHostStrict`,
  `bl.IsBlocked`, `pluginDecision`, the SSRF guard and `ssrfControl` run in the
  same order, all before the dial. Every failure path returns without dialling.
  The new hangup watcher reads **at most one byte**, hands it back, and is
  joined before the handler reads the connection again.
- **File permissions.** Every mode literal in the window's production diff is
  `0o600`/`0o700`/`0o750` and byte-identical to base. No rotated log, journal
  record, support bundle, lock file or archive batch lands looser than it did.
- **Journal content as an injection vector.** Every string leaving an
  interrupted-operation record is gated through a closed set or a regexp before
  it reaches a log line, an audit entry or the status body, and **nothing from a
  journal record reaches an exec argument or a shell** — the one journal-derived
  value that reaches a privileged call is re-validated by
  `validatePinnedDigestRef`. Forged-record tests pin each gate.
- **Shutdown ordering.** The OTLP flush hook is inserted at order 138 — after
  every durable closer, before the log closer — with no existing order constant
  moved. Audit writes are synchronous and unbuffered, so no audit record can be
  lost to it.
- **The legacy UI's new blocklist feedback.** `blReportAdd` renders the
  server-supplied `host` and `reason` through `escHtml` in element-text context;
  the only raw interpolations are numbers. The response is bounded at 50 notes.

---

## Findings

### A. A SOCKS5 client can erase its own request-log row by hanging up

**Severity:** Low. **Class:** insufficient logging (CWE-778), OWASP A09:2021.
**Regression:** yes, against `491b9630`.

`socks5.go:607-624`. Making the connect phase cancellable introduced an outcome
that is neither allowed nor blocked — the client left while the SSRF pre-flight
was still resolving — and the new branch returns with a log line and **no
`recordRequest` call**:

```go
if socks5ClientGone(ctx) && !errors.Is(err, errSSRFBlocked) {
    logger.Printf("SOCKS5 client closed during SSRF pre-flight %s -> %q", ...)
    return nil, nil, false
}
```

At base the guard ran under `context.Background()`, so it always ran to
completion and **every** non-nil error wrote a row
(`git show 491b9630:socks5.go:556-563`).

The in-code comment claims "a demonstrated private destination is ALWAYS
recorded". That holds only on a **cache hit**: `internal/ssrf/ssrf.go:273-278`
returns `ErrBlocked` from the cache before testing the context, but on a miss
the cancellation surfaces as `lookupAbandoned` (`ssrf.go:313-318`), which is
deliberately **never** `ErrBlocked`. So the waiver applies on exactly the probes
that matter: the first probe of a fresh name.

**Attack scenario.** Any source the IP filter, rate limiter and connection
limiter admit to the SOCKS5 listener completes the no-auth greeting, sends the
CONNECT request and a FIN in one flight, naming a unique label under a wildcard
record pointing at `127.0.0.1`. Repeat per probe: an internal-host sweep that
leaves no `status=BLOCKED` row.

**Preconditions:** SOCKS5 listener reachable; destination not already in the
SSRF DNS cache. **Exploitability:** easy and repeatable.
**Impact:** the structured request-log/SIEM trail for SOCKS5 internal-host
probing is lost. **No policy bypass, no SSRF, no oracle** — no reply is sent,
nothing is dialled, and the verdict is never computed, so the attacker learns
nothing. The attempt survives in the application log.

**Fix.** Record the attempt with a non-verdict status,
`socks5StatusAbandoned = "ABANDONED"`, instead of returning silently. The
verdict is still withheld — charging an SSRF refusal that was never
demonstrated is what `lookupAbandoned` exists to avoid — but the row, with its
client IP and destination, survives. A non-verdict status is the established
shape on this listener (`SHUTTING_DOWN`, `CONN_LIMITED`, `NOT_READY`), and the
Traffic console leaves an unlisted status neutral with no stated meaning by
design, which is the honest rendering for an undecided outcome.

### B. The end of a stale-intelligence episode is unrecorded on every node in the default posture

**Severity:** Low. **Class:** insufficient logging (CWE-778).
**Regression:** yes, against `491b9630` — introduced by the 2026-11-19
review's own latch fix.

`threatfeed_health.go` and `blocklist_feed_health.go`. At base,
`evaluateThreatFeedStaleness` set `alerted = true` **unconditionally** on a
stale verdict, before any subscriber check. SEC-TFEED/BLFEED-STALE-LATCH-1
correctly changed that so only a **dispatched** alert consumes the episode
(`latchOncePerEpisodeOnDelivery` sets `*latched` only if `delivered()`) — but
`alerted` is *also* the gate for the episode-ended log line:

```go
wasAlerted := threatFeedHealth.alerted      // false for the whole episode
...                                         // when nothing is subscribed
if wasAlerted && logger != nil {
    logger.Printf("ThreatFeed: sync recovered — ... (%d suppressed ...)", suppressed)
}
```

With no webhook configured — **the default posture** — `delivered()` returns
false, `alerted` never becomes true, and the recovery line never fires. The same
applies to both blocklist-plane lines (`noteBlocklistFeedRoundRecovered`,
`noteBlocklistFeedsRemoved`). The new ClamAV freshness plane
(`clamav_signature_freshness.go`) has the identical shape; for it there is no
base behaviour, so it is a new-code gap rather than a regression.

**Scenario.** An ordinary outage on a node with no webhook: the threat feed or
deny list goes stale and later recovers. **No attacker.**
**Impact.** The log keeps every failure line but loses the closing bracket and
the `suppressed` count — the two facts that bound how long the gateway enforced
against stale intelligence. Precisely on the nodes that page nobody and
therefore depend on the log. Unpinned by any test before this change.

**Fix.** Separate the two meanings. `latchOncePerEpisodeOnDelivery` gains a
`sawStale *bool` it sets for every live episode it is called in, dispatched or
not; each plane clears it wherever it clears `alerted`; the recovery lines are
gated on it. The paging latch is untouched, so the 2026-11-19 fix stands. The
ClamAV plane's inline latch gets the same split.

### C. A later image change retires an interrupted *data* rollback's recovery instruction

**Severity:** Low. **Class:** incomplete recovery record (CWE-778 / CWE-1059).
**Regression:** no — `journal_retire.go` is new in this window and base retired
nothing. A gap in a new control.

`cmd/culvert-maint/internal/server/journal_retire.go:88`. The retirement loop
skips only the retiring op's own record and ops running in-process; it does not
test the record's class. But its entire justification is *image-state*
reasoning — quoting the file's own header, the record "stops being true the
moment a later operation re-pins the tag, recreates the proxy and passes the
health gate". An interrupted **data** rollback claims neither: it says `/data`
may be half-restored, and it carries the only durable pointer to the recovery
procedure (`actionData`: "the agent does not repair the data directory …
follow 'Recovering from an interrupted restore'").

**Scenario.** An operator runs `POST /v1/rollbacks` with `mode=data`
(journalled `KindRollbackCreate`, `Mode:"data"`, classified
`DockerStateDataIndeterminate`). The agent is killed mid-restore. Startup
reports it with the recovery advice. The operator then runs a successful
`upgrades/apply` or `mode=image` rollback — `retiresInterrupted` is set
unconditionally for both — and the data record is removed. `/v1/status` goes
clean and the recovery instruction disappears while the data directory is
exactly as the interrupted restore left it.

**Preconditions:** operator on the agent socket; an interrupted data rollback;
a later successful image change. **Impact:** loss of a durable operator safety
warning. **Not an audit loss** — the `:interrupted_superseded` entry is written
before the removal, with the correct audit-then-mutate ordering.
Existing tests pin only which kinds may *retire*, never which may be *retired*.

**Fix.** Skip a record whose `DockerState` is `DockerStateDataIndeterminate`.
An image change establishes nothing about `/data`, and the agent does not repair
a data directory, so nothing it can do makes that record untrue.

### D. A webhook repoint is the one alert mutation with no destination in the audit log

**Severity:** Low. **Class:** insufficient logging (CWE-778), OWASP A09:2021.
**Regression:** no — the PUT arm was identical at base. Raised because this
window changed its sibling and left the pair asymmetric.

`ui_security.go:154` recorded `auditEvent(r, "alert.webhook.update", id, "")`
while this window changed the create arm to record `alerts.URLOrigin(h.URL)`.
`PUT /api/alerts/webhooks?id=X` accepts a full body including a **new URL**, so
an operator who repoints the SOC's webhook at their own endpoint leaves an
audit record naming no destination at all. Role enforcement is correct
(`RoleOperator`); this is insider abuse and post-incident forensics, not
privilege escalation.

**Fix.** Record `alerts.URLOrigin(h.URL)`, matching the create arm — the origin,
never the path/query/userinfo that *is* the credential. A URL-less PUT (where
the store preserves the existing URL) records nothing rather than an empty
origin that would read as "repointed to nowhere".

### E. The webhook name in the delivery-error log is not sanitized

**Severity:** Informational. **Class:** CWE-117.
**Regression:** no — the same sinks' `h.Name` was unsanitized at base; the diff
changed only the error formatting on that line.

`internal/alerts/store.go:1235` printed `h.Name` with `%q` but without
`obs.Sanitize`, while the sibling 18 lines above applies both. `%q` already
escapes control characters, so there is no live log-injection vector — this is a
`conventions.md` consistency gap on a line this window touched, fixed so the two
siblings cannot drift.

---

## Reported, not fixed

- **`dp_enrollment.go:150-151` inherits the 128 MiB cluster-snapshot receive
  bound** on a channel that uses `insecure.NewCredentials()`. An on-path
  attacker can answer the one-shot `Enroll` with a ~128 MiB frame that the
  enrolling node buffers and unmarshals before `verifyCAFingerprint` runs.
  **Not a regression:** at base the call carried gRPC's 4 MiB default but could
  not succeed at all (no `ForceCodecV2(rawCodec{})`), so there is no working
  base behaviour this loosened. The same network position already permits full
  CP impersonation when the join URL lacks `?ca-fp=`, which the code warns
  about. Worth an enroll-sized `MaxCallRecvMsgSize` override (the response is a
  cert plus a CA PEM) — a deliberate change to a startup path, not a
  regression fix, so it is left to its owner.
- **The pinned-tag realignment after a failed `up` is not audited.**
  `journal_phases.go:197-220` moves `culvert/proxy:pinned` back to the prior
  ref, and the only record is a host-filesystem-only op-log note; no route
  exposes op logs, and `upgradeApplyResult` records `final_running_digest` but
  never where the tag now points. The argument itself is safely gated
  (`validatePinnedDigestRef` + the allowlist), so this is audit completeness,
  not an injection or authorization gap. Four outcomes need one audit kind
  each, modelled on `emitRollbackAudit` — more than a one-line fix, and it
  belongs with the owner of that flow.
- **`internal/geoip/deferred.go:73-78` advances `geoLoadAt` on every retry**, so
  the admin panel's `lastErrorAt` always reads "within the last two minutes"
  however long GeoIP has been unloadable — and while it is, country **BLOCK**
  rules do not match. A regression in forensic value (base wrote it once, at
  startup) introduced by a change that otherwise *narrows* the fail-open window
  by retrying without a restart. The fix is a separate first-failure timestamp
  surfaced alongside `lastErrorAt`, which is an API addition.
- **`blocklist_feed_health.go:385-392` overstates its own invariant.** The
  comment says "the sink only probes the lock-free subscription index", but
  `delivered()` now runs under the plane mutex and can reach
  `armSubscriptions`, which takes the alert store's **write** lock. No
  lock-order inversion exists today (nothing holding the store lock acquires a
  plane lock, and `Init` publishes the index before these planes evaluate), so
  it is not a defect — but the comment should be made true or restated before
  someone adds a store path that calls back into a health plane.
- **PRE-EXISTING: `journal.List()` fails closed on any non-ULID-named `.json`
  file** under the agent's `reconcile/` directory, and `initJournal` turns that
  into "refusing to serve", so one planted file permanently stops the
  maintenance agent. The directory is `0750` and agent-owned, and the posture is
  documented as intentional with quarantine left as an open decision (ADR-0061).
- **PRE-EXISTING: the SOCKS5 SSRF-block branch does not increment
  `statBlocked`** although the blocklist and plugin branches immediately above
  it do, and `socks5Reply` discards its write error. Both predate `491b9630`.

---

## Verification

| Check | Result |
|---|---|
| `go build ./...` (root) and `cmd/culvert-maint` | **PASS** |
| `go vet` on every changed package | **PASS** |
| Root module `go test ./...` | see the pull request |
| `cmd/culvert-maint` `go test ./...` | see the pull request |
| `golangci-lint` at the gate's pinned `v2.15.0`, built with the `go.mod` toolchain | see the pull request |
| Finding A gate reverted against merged main | **FAIL** — "the attempt was not recorded at all" |
| Finding B gates reverted against merged main (all three planes) | **FAIL** — "the end of a stale-intelligence episode went unrecorded" |
| Finding C gate reverted against merged main | **FAIL** — "retired [01HZZ…], taking the interrupted data rollback's recovery instruction with it" |
| Finding D gate reverted against merged main | **FAIL** — the update entry's `detail` is `""` |

New gates, each proven to fail against the code as merged and pass against the
fix, with a positive control that prevents a vacuous pass:

- `TestSOCKS5_AbandonedPreflightStillRecordsTheAttempt` — a cold-cache probe
  with a hangup must leave an `ABANDONED` row carrying the client IP; the
  control `TestSOCKS5_DemonstratedPrivateDestinationStillRecordsBlocked` pins
  that a demonstrated private destination is still `BLOCKED`, so a fix cannot
  downgrade a real refusal.
- `TestThreatFeedRecovery_IsLoggedWithNoSubscriber`,
  `TestChaos123_RecoveryIsLoggedWithNoSubscriber`,
  `TestRecoveryIsLoggedWithNoSubscriber` (ClamAV) — stale→recovered with the
  sink reached and nothing dispatched must log the recovery line; each has a
  `…SilentWhenNeverStale` / `…IsSilentWhenNeverStale` control so the gate cannot
  be satisfied by logging unconditionally.
- `TestRetire_DoesNotRetireADataRollbackRecord` — asserts the seeded record
  really classifies as `DockerStateDataIndeterminate` before asserting it
  survives; `TestRetire_StillRetiresAnImageRecord` is the control that the
  filter did not stop retiring everything.
- `TestAlertWebhookUpdate_AuditRecordsTheNewOriginNotTheCredential` — the new
  origin must appear in the viewer-readable audit log and the path/query
  markers must not.

**Not run, and why.** CodeQL and the hosted Fast PR Gate run on the pull
request; they are the authorities for their own checks, and a passing local
check is not a passing merge gate. The frontend vitest suite needs
`frontend/node_modules`, absent here — no frontend source was changed by these
fixes. The `startup_crash_recovery_test.go` end-to-end rig builds and launches
the agent binary and was not run; the journal-retirement change is covered by
the server-package tests above.

---

## Residual risk

- **The "one flag, two meanings" shape is the real lesson of Findings B and C,
  and it is structural.** Both came from a correct fix narrowing when a flag is
  set, without noticing a second reader that depended on the old breadth. The
  `sawStale` split fixes the three instances found; nothing prevents the next
  one. A plane that needs "did this episode happen?" should not read the paging
  latch, and that is now true in three places by convention, not by
  construction.
- **Finding A's siblings record nothing at all.** The HTTP CONNECT, WebSocket
  and inspect SSRF-block sites log only and have never written a request-log
  row, so SOCKS5 remains the outlier in having one. The fix restores SOCKS5's
  own coverage; it does not give the other three paths the row they never had.
  Whether a blocked HTTPS CONNECT to an internal host deserves a structured row
  is an open question worth asking.
- **The ABANDONED status reaches `/metrics` consumers and SIEM exports as a new
  value.** `reqlog.LevelForStatus` maps it to `ERROR` by its default arm, which
  is where every other non-verdict status already lands. Dashboards filtering on
  an explicit status list will not show it until updated; the Traffic console
  renders it neutral by design.
- **Sidecar-mode deployments get no ClamAV freshness signal.** The remote
  `/scan` protocol does not carry the sidecar's signature identity, so
  `checkClamAVSignatures` returns no row at all there — the staleness this
  window learned to detect is undetected in exactly the deployment that
  centralises scanning. Recorded by the code; worth a protocol field.
- **A future-dated or unreadable ClamAV build date is deliberately not paged.**
  It is an inability to measure, not evidence of staleness, so it gets a row and
  a gauge. A daemon whose clock is wrong therefore has no definition-age check
  at all, and nothing pages about that.
- **The new `IsRegular` refusal in `openLogAppend` would break an undocumented
  `audit_log_file=/dev/stdout` or symlinked log path**: the open fails, the
  audit log falls back to the in-memory ring, and the deferred retry fails
  forever while the proxy keeps serving. Canonical configuration is a regular
  file under `/data` and nothing in the repository documents otherwise, so this
  is a supported-configuration note rather than a finding.
- **Nothing in this review validates the hosted gates.** CodeQL's dataflow view
  of the changed log sinks and the Fast PR Gate's `--new-from-rev` plus
  full-tree lint comparison are the authorities for their own checks.
