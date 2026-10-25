# Chaos engineering review — 2026-10-24

Base: `a27cffb` (merged `main`). Branch: `claude/serene-cerf-r814m7`.
Id claimed: **CHAOS-101** (the scan sidecar's own buffer window), allocated in a
committed placeholder row as commit one per the id-claiming convention in
[the register](../../roadmap/CHAOS-ENGINEERING-REVIEW.md). It was first claimed
as CHAOS-88 (86 was the highest id written up there; 87 was held by the open
sweep in PR #1485), but 88 was also allocated to the open sweep in PR #1564 and
89–100 were taken or allocated before this merged, so it was renumbered to 101.
Only the id moved.

Scope of this sweep: the **content-scanning plane** (the fixed finding), plus a
breadth pass over the **intelligence/enrichment feeds** and the
**observability/durability plane**. Every claim below was verified by reading
the source at this revision. Items marked **REPORTED (verified)** are real and
deliberately **not** fixed here, with the reason given.

---

## Executive summary

One defect is fixed: the scan sidecar answered `clean: true` for bodies it had
only partially read. Culvert's remote-scan **client** is, on the evidence, one
of the most carefully hardened paths in the tree — a prior sweep gave it a
three-way posture switch, an "a verdict must be AFFIRMATIVE" rule that rejects
`{}`/`null`/a load balancer's JSON page, locally-computed hashes so a
compromised sidecar cannot name objects in the operator's allowlist, bounded
alert-dedup classes and rate-limited degraded logs. The **server** on the other
end of that contract had none of the same attention, and it was the hole: it
read `LimitReader(body, maxBytes+1)`, never looked at the probe byte, and
reported the prefix verdict as the whole object's.

The two scan windows are independent by construction — each process computes
`maxScanBufferBytes()` from its own `security.max_scan_mb` — so no code bug
is needed to reach this, only a 20 MiB proxy fleet in front of a sidecar left at
the 5 MiB default. Scanning is then off for every byte past 5 MiB with **no
counter, no log line and no alert anywhere in the fleet**, and the caller's own
overflow signal correctly does not fire, because the body fit the caller's
window. That is the pure silent-failure shape, in the deployment the capacity
runbook recommends as the remedy for the in-process path's failure modes.

The most important thing this sweep learned is about the **fix**, not the bug.
Refusing oversize reads before scanning — the obvious shape, and the first draft
here — makes the system **less** safe: a body whose malware sits inside the
window becomes a 413, the client classifies that as a size limit and forwards
fail-open, so the one case where the sidecar holds a real block verdict is the
case the "safe" check throws away. It would have admitted content the unfixed
code blocked. A negative control written before the fix caught it. This is the
same shape the register records for CHAOS-75, where adding `runGuarded` and
nothing else resolved a race the wrong way 10 times out of 10.

The breadth pass found no second defect in the scanning plane and four verified
findings elsewhere, none fixed here. The sharpest is that the **cluster audit
trail is not durable at all**: the Control Plane acks `{"ok":true}` for a push
that lands in a 5000-entry in-memory ring with no counter and no file writer,
the Data Plane then clears its queue permanently, and a prior review's
hang-risk analysis of that very handler states as its premise that it "appends
to a `fileutil.RotatingFile`". It does not. That premise is corrected in this
PR; the durable sink it implies is an owner decision.

---

## Failure scenarios

### CHAOS-101 — the sidecar reported a truncated read as clean (FIXED)

**Current behavior (before).** `scan_svc.go` `handleScan` read
`io.ReadAll(io.LimitReader(r.Body, maxBytes+1))` and never compared
`len(data)` against `maxBytes`. The `+1` is the classic overflow probe; the
handler paid for the byte and discarded the information. `resp.Clean` stayed
`true` whenever the prefix was clean, and the reply carried no truncation
field — `secscan.ScanResponse` has none.

**Expected behavior.** The in-process path at `proxy_tunnel.go:1325` buffers
`maxScanBufferBytes()` and, when the body runs past it, fires the operator's
only notification that bytes went unscanned:
`readScanPrefix`'s deferred `onOverflow` → `logScanLimitExceeded`
(`security_scan.go:236`), which charges `statScanSkipped`, logs once and
fires the `scan_skipped` alert with `Source: "size_limit"`. The sidecar
serves the same engines and owed the same signal.

**Failure mode.** Silent scan evasion. Reached by configuration alone:
`maxScanBufferBytes()` (`security_scan.go:148`) maxes the DPI engine's limit
over `globalSecScanner.MaxBytes()`, which comes from that process's
`security.max_scan_mb` (`scanning_startup_config.go:89-91`). Nothing
reconciles the caller's window with the sidecar's. The handler's own doc comment
("multiple proxy instances sharing one scanner", "any other process on the
same host/network") invites exactly the topology where they drift.

**Customer / security / operational impact.** Malware past the sidecar's window
is admitted and reported clean. No surface exposes it: the proxy's
`culvert_scan_skipped_total` stays flat because the proxy's window was not
exceeded, `culvert_remote_scan_fail_total` stays flat because there was no
fault, and the sidecar logged nothing. An operator cannot discover this from
any surface the product exposed.

**Fix.** `handleScan` now uses the probe byte, and — ordering being the whole
correctness argument — decides the refusal **last**, only for a prefix that came
back clean. A block verdict wins and truncation is not reported at all on a
block, the same asymmetry `readScanPrefix` documents for the local path. The
engines see `data[:maxBytes]`, so what is scanned stays byte-identical to
`LimitReader(body, maxBytes)` and the hash the client computes still describes
the bytes it sent. `/health` publishes `oversize_refused` and
`scan_window_bytes`: the sidecar is the only process that knows its window,
and the operator needs it to compare against the caller's.

Client side, `internal/secscan/remote.go` classifies 413 as
`remoteOutcomeOversize` and `remoteScanOversize()` charges the **local
path's** vocabulary — `statScanSkipped`, hence
`culvert_scan_skipped_total`, and the `scan_skipped` alert with
`Source: "size_limit"` — for the same reason `remoteScanRefused` reuses the
timeout vocabulary: it is the same decision. One phenomenon keeps one counter
and one alert class whichever window clipped the object. A load balancer in
front of the sidecar enforcing its own smaller body limit returns 413 for the
same reason, so the classification is right for that topology too; every other
status keeps its fault classification, pinned by a negative control.

**Posture (open half).** The fix preserves the local path's recorded posture for
oversize bodies: **fail-open, counted and alerted** (Finding 4.2 / WK-2b).
Refusing the object outright is the safer answer and a real option, but it is a
posture change for large downloads that no operator asked for. It belongs to the
owner, not to the fix that makes the event visible.

### REPORTED (verified, not fixed): the cluster audit trail is not durable, and the ack says it is

`controlplane_server.go:383-385` calls `globalClusterAudit.Append(...)` and
returns `{"ok":true}`. `globalClusterAudit` is `&clusterAuditLog{maxSize:
5000}` (`controlplane.go:279-285`) — a mutex, a slice, and a trim at
`:296-299` with **no counter, no log line and no metric**. `grep
ClusterAuditEntry` over non-test sources returns only `controlplane.go`:
there is no file writer on this path anywhere. The DP requeues **only** on RPC
error (`controlplane_client.go:724-728`), so on `ok:true` the events leave
`audit.pending` permanently.

Two consequences. A CP restart or crash evaporates the entire centralized audit
trail, and >5000 events between dashboard reads (`ui_cluster.go` reads
`Recent(200)`) silently evict the oldest — while
`culvert_audit_cluster_push_drops_total` stays 0, because that counter charges
only the DP-side cap overflow (`internal/audit/audit.go:450-471`).

The durability was **believed to exist**: `controlplane_server.go:1034-1035`,
reasoning about handlers that block on a wedged volume, states that
"PushAuditEvents appends to a `fileutil.RotatingFile`". That premise is false,
which also means that sweep's hang analysis for this handler does not hold.
**This PR corrects the comment and nothing else** — a durable sink's location,
retention, backup interaction and cluster-sync semantics are an owner decision
of the same shape the register deliberately left open as WK-22, not something to
invent inside a sweep. `distributed_rl_test.go:365,398` currently assert the
ring trim as intended behavior; nothing asserts durability or a drop counter.

Compliance-relevant: this is the audit trail.

### REPORTED (verified, not fixed): a logstore batch-flush failure is log-only, and the gauge keeps claiming it is saving

`internal/logstore/logstore.go:481-485` — `wb.Flush()` error logs
`obs.Printf` and discards up to 256 entries with **no counter**; the package
has only `statDropped` (queue-full) and `statPruned`. The `json.Marshal`
error at `:469-471` is a bare `continue`, also uncounted — the exact branch
`internal/audit` charges deliberately at `internal/audit/audit.go:246-253`.

On a full, read-only or EIO history volume, every surface reports healthy
simultaneously: `culvert_logstore_dropped_total` stays 0,
`culvert_logstore_available` stays 1 — and its HELP string at
`metrics.go:1185` literally reads "1 when the request-history store is open
**and saving history**", while `Available: true` is set once at open in
`noteLogStoreOpened` (`logstore_health.go:110-117`) and never revisited —
and `/api/diagnostics` shows `request_history` as `diagOK`. No alert, even
though the `storage_write_failed` plane already exists and is wired for
audit/fileutil at `storage_health.go:124-144`.

Secondary: that `obs.Printf` is unthrottled on a ≤500 ms flush ticker, against
the "count EVERY failure, log only the FIRST" contract the sibling states at
`internal/audit/audit.go:72-75` — and on a shared volume it floods a log sink
whose own writes are failing. No test covers the write path.

Not fixed here because the fix is a new counter plus a health/metric surface in
a domain this PR does not otherwise touch, and GUI/API parity applies.

### REPORTED (verified, not fixed): the flush-phase post-mortem is written into an already-closed sink

`main_shutdown.go:149-151` logs `"Shutdown (%s phase) error(s): %v"`
**after** `reg.RunAll` returns, and `shutdownOrderLogCloser = 140`
(`:219`) is the last flush hook — the sink is already closed. A post-`Close`
`Write` wins the non-blocking `case w.ch <- bp` (the drain emptied the
buffer), returns `len(p), nil`, and the line sits in a channel nobody reads:
not charged to `writeErrors`, not to `backpressure`
(`internal/logsink/logsink.go:140-148`).

So when `syslog-close`, `community-db-close`, `log-store-close`,
`request-log-close` or `audit-log-close` fails or is abandoned by the
watchdog on a wedged volume, the line naming **which** durable close failed
never lands, and `culvert_logsink_write_errors_total` stays 0. The next boot
quarantines an uncleanly-closed store with no record of why — the scenario
`main_shutdown.go:30-37` says this budget work exists to preserve. The
codebase is half-aware: `:116-119` already moved the *completion* line ahead
of the flush phase for this reason; the error path did not get the same
treatment. `internal/reqlog/persist.go:306-316` is the in-repo pattern that
does it right, sweeping the abandoned channel and charging each stranded entry.

### REPORTED (verified, not fixed): a UT1 tarball yielding zero entries is recorded as a fully successful sync

`internal/feedsync/feedsync.go:317-336` — `downloadAndParse` returns
`(entries, nil)` with no minimum-size gate, `BulkWrite` on an empty map
succeeds (`internal/catdb/catdb.go:325-336`, pinned intended by
`TestCommunityDB_BulkWrite_Empty`), and the success block then stores
`lastSync = now`, `totalDomains = 0`, `consecutiveFailures = 0`,
`lastFailure = ""`.

Reached by a layout change at a third-party origin: `classifyTarEntry`
(`:438-450`) requires **exactly three** path components, so any repack that
adds a top-level directory (`<repo>-<ref>/blacklists/adult/domains`, the
codeload convention) makes every entry fall through. Category rules then fail
to match via `policy_hostcat.go:251-257`, so an enforcing
`Deny category=Malicious` becomes a silent no-op for every host only UT1
covered, while `culvert_category_feed_last_sync_timestamp_seconds` stays fresh
and `culvert_category_feed_sync_failures_total` stays flat. `RunNow` fires
each boot, and every round "succeeds" with 0 domains — permanently.

This is an **asymmetry, not a preference**: `internal/threatfeed` decided the
opposite way with the reasoning written down at `threatfeed.go:435-451` —
`n == 0` is a failure and previous data is carried forward, because "these
public feeds are never legitimately empty, so treating it as clean would wipe
the feed the same way a hard error used to (caught by review on PR #587)".
`feedsync` has no equivalent gate and no zero-entry test.

### REPORTED (verified, not fixed): the SaaS feed's retry can loosen the cadence ~6×

`saas_feed_scheduler.go:185-200` — `backoffDelay` is a package-level
function with no access to the interval, ceiling fixed at
`saasFeedBackoffMax = 6h`; the operator-settable refresh floor is
`saasFeedMinRefresh = 1h` (`saas_feed_config.go:40`). After ~9 consecutive
failures a node retries every 6 h while a healthy node on the same config polls
hourly, and the last-known-good generation can age past its manifest expiry
while waiting. The recovery mechanism becomes an extra delay.

Also an asymmetry against a documented sibling: `internal/feedsched`'s
`backoffBounds` (`feedsched.go:272-299`) clamps **both** floor and ceiling to
the live interval to uphold "retrying only ever tightens the cadence", noting
"the first shipped version got this wrong (caught in review on PR #1305)… a
failed round waited FIVE TIMES LONGER than a healthy one". The main-side
scheduler predates `feedsched` and never received the clamp. Its existing gate
`TestF3b4_Scheduler_BackoffDelayBounds` cannot catch it: it asserts only
`backoffDelay(1)`, `(100)` and `(0)` against the constants, never
`backoff ≤ interval`.

---

## Risk matrix

| Id | Finding | Likelihood | Customer | Security | Data integrity | Visibility | Status |
|---|---|---|---|---|---|---|---|
| CHAOS-101 | Sidecar reports truncated read as clean | **Medium** (config drift between planes) | Low | **High** (silent scan evasion) | None | **None → full** | **FIXED** |
| — | Cluster audit trail not durable; ack claims success | **High** (any CP restart) | Low | **High** (audit loss, compliance) | **High** | **None** | Reported |
| — | logstore flush failure uncounted; gauge claims saving | **High** (any full/RO history volume) | Medium (history gaps) | Medium (lost forensics) | **High** | **None → wrong** | Reported |
| — | Flush-phase post-mortem written to closed sink | Medium (needs a failing close) | Low | Low | Medium (diagnosis lost) | **None** | Reported |
| — | UT1 zero-entry sync recorded as success | Medium (3rd-party layout change) | Medium | **High** (category Deny becomes no-op) | Low | **None → wrong** | Reported |
| — | SaaS feed backoff loosens cadence ~6× | Medium (any repeated origin failure) | Low | Medium (stale feed past expiry) | None | Partial | Reported |

---

## Recovery assessment

- **CHAOS-101, automatic:** none needed and none attempted — the condition is a
  standing configuration mismatch, not a transient fault. Recovery is
  **operator-driven and now possible**: `scan_window_bytes` on the sidecar's
  `/health` plus the `scan_skipped` counter and alert on the proxy name both
  halves of the mismatch. Aligning `security.max_scan_mb` resolves it with no
  restart coordination. Before the fix there was nothing to recover *from*,
  because nothing reported a problem.
- **CHAOS-101, deterministic:** yes. The refusal is a pure function of
  `len(data) > maxBytes` on bytes already in hand; no timing, no retry.
- **Cluster audit, manual only:** lost entries are unrecoverable. The local
  per-node JSONL is unaffected, so the magnitude is "centralized trail only" —
  reconstruction means collecting per-node files by hand, and nothing records
  that it is necessary.
- **logstore, none:** a failed batch is discarded in-process. Recovery requires
  noticing, which is the finding.
- **UT1 zero-entry, automatic but wrong direction:** each boot's `RunNow`
  re-succeeds with 0 domains, so the broken state is actively re-affirmed rather
  than decaying into a staleness signal.

---

## Operational impact

The fixed finding changes one thing operationally: a fleet with mismatched scan
windows starts emitting `scan_skipped` and refusing those bodies at the
sidecar instead of silently admitting them. **Operators running such a
deployment today will see new alert volume on upgrade** — that volume is the
defect becoming visible, not a regression, and the remedy is named in the log
line ("align them") and measurable from `/health`. Large downloads continue to
be forwarded, unchanged.

The four reported findings share one operational signature worth stating
plainly: **every one of them reports healthy while failing.** Three
(`culvert_logstore_available`, the category feed's fresh timestamp, the CP's
`ok:true`) do not merely omit a signal, they actively assert the opposite, and
one of them (`culvert_logstore_available`'s HELP text) documents a guarantee
the code does not implement. An operator's dashboard is not a reliable
indicator of the durability or enforcement state of these four planes.

---

## Security impact

CHAOS-101 was a scan-evasion hole: content past the sidecar's window was admitted
with an affirmative clean verdict. It required no attacker capability beyond
choosing a response size, and no code bug — only two processes configured
independently, which is what the sidecar's own documentation recommends. The
in-process path had already been given a signal for this exact event; the
process-isolated deployment, recommended as the *remedy* for the in-process
path's weaknesses, was the one without it.

The fix's first draft would have made this worse, and the mechanism is worth
recording: a size check placed before the scan converts a **real block verdict**
into a fail-open forward, because the client (correctly) treats a size limit as
a non-fault. Any future change to `handleScan` that reorders the refusal ahead
of the verdict re-opens it; `TestScanSvc_MatchInsideWindowStillBlocks` is the
gate that fails if it does.

Of the reported findings, the audit-durability one is security-relevant on its
own terms — an audit trail that silently loses entries while acking success
undermines every investigation that depends on it — and the UT1 zero-entry one
turns an enforcing category Deny rule into a no-op, which is a policy bypass
reached without touching Culvert at all.

---

## Suggested improvements (beyond this PR)

1. **Give the cluster audit trail a durable sink**, and correct the two things
   that currently hide its absence: the unconditional `ok:true` and the
   uncounted ring trim. The DP should not clear `audit.pending` on an ack the
   CP cannot honor. Needs an owner decision on location, retention, backup and
   cluster-sync.
2. **Count logstore write-path failures** (`wb.Flush` and the `json.Marshal`
   `continue`), route them into the existing `storage_write_failed` plane,
   and make `culvert_logstore_available` mean what its HELP string says — or
   change the HELP string. Throttle that `obs.Printf`.
3. **Emit the flush-phase error line before order 140**, or sweep the abandoned
   logsink channel and charge the stranded lines, as
   `internal/reqlog/persist.go` already does.
4. **Give `feedsync` threatfeed's zero-entry gate** — treat 0 mapped entries
   as a failure and keep the previous generation — and a layout-drift signal, so
   a repack at the origin is loud rather than a permanent silent success.
5. **Clamp the SaaS scheduler's backoff to the live interval**, reusing
   `feedsched.backoffBounds`' logic rather than re-deriving it, or complete the
   migration `feedsched.go:70-72` records as a follow-up.
6. **Consider a wire-level truncation field** on `ScanResponse`. 413 carries
   the signal adequately and needed no wire change, but an explicit field would
   let a future sidecar report a partial scan *with* a verdict, which the status
   code cannot express.

---

## Required tests

Shipped with this PR:

- `scan_svc_window_chaos_test.go`
  - `TestScanSvc_TruncatedBodyIsNeverReportedClean` — the defect gate; fails
    against `main`.
  - `TestScanSvc_MatchInsideWindowStillBlocks` — **the ordering control**, and
    the one that earned its place: it failed against the first draft of this
    fix, where the refusal preceded the scan and converted a block into a
    fail-open forward.
  - `TestScanSvc_BodyExactlyAtWindowStillScansClean` — boundary control; a body
    of exactly `maxBytes` was read whole and keeps its real clean verdict.
  - `TestScanSvc_OversizeRefusalIsCountedAndOnHealth` — the sidecar-side
    counter and the published window.
- `internal/secscan/remote_oversize_chaos_test.go`
  - `TestChaos101_OversizeRefusalIsASizeLimitNotAFault` — 413 charges
    `ScanSkipped`, and leaves `RemoteScanFail`, `ScanTimeout` and
    `RemoteScanSaturated` alone.
  - `TestChaos101_OversizeFiresTheScanSkippedAlert` — alert class and
    `Source: "size_limit"`, asserted on content per the package's stragglers
    doctrine.
  - `TestChaos101_OversizeDoesNotFireTheSidecarDownAlert` — refutes the
    misclassification that would page on-call for a healthy sidecar.
  - `TestChaos101_OtherStatusesAreStillFaults` — keeps the new branch narrow
    (500/404/400 stay faults).
  - `TestChaos101_OversizeLogIsRateLimitedWhileTheCounterStaysExact` — the
    throttled-line / exact-counter split.

Owed by the reported findings, none of which has one today: a CP-restart audit
durability test and a ring-overflow drop-counter test; a logstore
`wb.Flush`-failure fault-injection test asserting a counter and the health
surface; a flush-phase-failure test asserting the error line reaches the file;
a `feedsync` zero-entry and unexpected-layout test; and a
`backoff ≤ interval` property test for the SaaS scheduler, of the shape
`internal/feedsync/sync_cadence_test.go:47` already has.

---

## Residual risk

- **CHAOS-101 does not make the two windows agree.** It makes the disagreement
  visible and stops it being answered as "clean". A fleet that ignores the new
  alert still forwards large bodies unscanned — by the local path's recorded
  posture, deliberately. Closing that is the posture decision left to the owner.
- **The 413 classification is status-based, not content-based.** Anything in
  front of the sidecar that returns 413 for an unrelated reason will be charged
  as a size limit. This is the correct reading for the body-limit case that
  motivates it, and the alternative — a wire field — is listed above as an
  improvement rather than taken here, because it would break the sidecar's
  compatibility with older clients in the mixed-version window.
- **The sidecar remains unauthenticated**, so `/scan`, `/health` and `/status`
  are reachable by anything that can reach the listener — and `/health` now
  publishes `scan_window_bytes` and `oversize_refused` to that same
  unauthenticated caller. Both are deployment-shape facts rather than secrets,
  and the exposure itself is already tracked, rated High, with a
  loopback/mTLS/token follow-up recorded in
  [the API consistency risk register](../api/API-CONSISTENCY-RISK-REGISTER.md)
  §9. This sweep did not revisit it.
- **Four verified findings are left open**, three of which actively report
  healthy while failing. They are recorded with file:line evidence rather than
  fixed, to keep this PR to one contract; nothing in this PR improves them.
- **Breadth, not completeness.** The feed and observability passes were bounded
  question sweeps over named owners, and their critical evidence was re-read at
  this revision by the author rather than taken on a worker's summary. Domains
  this sweep did not open at all include CDR, OCSP, SOCKS5, the CA/enrollment
  plane, release dispatch and the frontend.

---

## Correctly handled — citable resilience paths

Recorded so later sweeps do not re-dig, and because several of these are the
precedents the fix above reuses:

- **The remote scan client's posture switch** —
  `internal/secscan/remote.go:246-291`: budget/capacity fail **closed**,
  faults fail open and counted, and a 200 without an affirmative `Clean` is a
  fault, not a verdict. The `Result.Hash` is computed locally, never taken
  from the sidecar, specifically so a compromised sidecar cannot name objects in
  the operator's allowlist.
- **The in-process scan window's overflow signal** — `readScanPrefix`
  (`security_scan.go:182-210`): the signal is deferred rather than probed, so
  a streaming body of exactly `limit` bytes that pauses without EOF cannot be
  withheld indefinitely; block paths never signal, because they never forward
  the tail.
- **GeoIP's country predicate** — `policy.go:2194-2211`: a cache miss means
  the rule does not match (fail-closed), with the user-visible-block consequence
  for allow-rules written out, and the miss counted via
  `culvert_geo_policy_unresolved_total`.
- **Threat feed staleness and partial failure** — `threatfeed_health.go:326-366`
  separates never-synced from stale, handles negative age from NTP steps, derives
  `LastRoundOK` from the persisted error rather than a non-persisted counter,
  and fires once per episode; `applySync`/`carryForward` replace only
  cleanly-fetched sources.
- **The shared feed cadence engine** — `internal/feedsched/feedsched.go:338-392`:
  interruptible on `ctx.Done()` before and after the timer, `ctx.Err()`
  re-checked per round, panic charged as a failure so there is no hot loop.
- **Audit JSONL durable-write visibility** — `internal/audit/audit.go:76-170`,
  wired into the storage-health plane at `storage_health.go:124-145` and
  surfaced on `/metrics`, `/healthz` and the admin UI. This is the shape the
  logstore finding above is missing.
- **logsink saturation** — bounded 4096 queue that **blocks** rather than drops
  (deliberate: it is the operator's record), per-line `WriteErrors`/
  `Backpressure` accounting, and a bounded `Close`/`Sync` so a wedged
  volume cannot hang shutdown.
- **Panic-containment doctrine** — `internal/obs/guard.go:19-38`: guard the
  loop *body*, never the goroutine, because a goroutine-level recover converts a
  loud crash into a silent permanent stall. The long-lived loops in the
  observability plane follow it, so a panic there is a crash, not a silent stop.
- **Bounded caches that look unbounded** — `internal/geoip` caps at 50 000 with
  bulk eviction; main's `hostIPCache` is capped with single-flight.

---

## Verification

Toolchain `go1.27.3` (`go env GOVERSION`), `GOTOOLCHAIN=auto`, matching
the root `go.mod` `toolchain` pin. Run at the branch head.

| Check | Result |
|---|---|
| `go vet ./...` | pass |
| `go mod tidy -diff` | clean (no dependency change) |
| `CGO_ENABLED=0 go build -ldflags="-s -w"` | pass |
| `go test -race -shuffle=on -count=2 ./internal/secscan` | pass (29.9s) |
| `go test -run 'TestScanSvc_' -count=1 .` | pass |
| `go test -run 'TestChaos101_' -count=1 ./internal/secscan` | pass |
| `TEST_SEED=20260421 go test -race -count=2 -shuffle=on -timeout=40m .` | see PR body |

Defect reproduction, recorded before the fix:
`TestScanSvc_TruncatedBodyIsNeverReportedClean` fails against `main` with
"sidecar answered 200 clean=true for a body truncated at its 4096-byte window
(4182 bytes posted)", while both negative controls pass — so the gate is
measuring the defect and not merely the new code. The ordering control then
failed against the first draft of the fix with "status = 413, want 200 carrying
the block verdict", which is what drove the final ordering.

Not run, and why: `make api-verify` and the route/metadata parity suites (no
admin API route, `uiRoutes` entry or schema changed — the sidecar's `/scan`
and `/health` are not admin-plane routes); the frontend tree (untouched);
`cmd/culvert-maint` (separate module, untouched); the `benchgate`-tagged
wall-clock gates (no hot-path or admission change). A passing local selection is
not aggregate CI approval; the required `✅ Fast PR Gate — APPROVED` and
`✅ Deep PR Gate — APPROVED` verdicts are the gate.
