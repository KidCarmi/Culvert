# Security regression review — alert-dispatch plane and the CI reporter

**Date:** 2026-09-23
**Head reviewed:** `3febe59` (PR #1477, *CI-REDESIGN stage 6B*).
**Predecessor:** `2026-09-05-mcp-canary-physical-effect-window.md` (closed at `290e376`).
**Branch:** `claude/epic-bardeen-hk1xn7`.

**Verdict: five defects found and fixed — one Medium, two Low-Medium, two Low —
all in the alert-dispatch plane. No authentication, authorization, policy, TLS,
crypto, trust-boundary or fail-closed regression was found in the reviewed
surface.**

---

## 0. Scope and method — stated precisely

The window since the predecessor review is very large (896 files, +234 720 /
−6 344, most of it `frontend/dist` and roadmap prose). **This review did not read
all of it, and does not claim to.** It was prioritised, and the priorities are
stated so a later reviewer knows what is still unread:

1. **The newest landed change in full** — PR #1477, the stage-6B CI performance
   reporter (`cmd/cireport`, `.github/workflows/ci-perf-report.yml`, the QA/Fast
   gate edits and the three test-wall edits). New code with the least
   accumulated review, and it consumes artifacts across a trust boundary.
2. **A whole-tree sweep of one defect class** — every alert producer reachable
   from the request path, checked against the two halves of the contract
   `CLAUDE.md` already states for them (`HasSubscriber` gating, bounded alert
   `Detail`). This is where all four findings are.
3. **Execution of the repository's own structural invariant gates** — the route
   metadata parity layer (C1/C1.5/C2/C2c/C4), the D0 baseline, the
   `configSurfaces` registry wall, the SOCKS5 destination-sink and
   log-sanitisation walls, the release-identity SSOT and the redaction walls.
   All passed on the unmodified tree.

**Not reviewed in this window, and explicitly left open:** the MCP subsystem
delta, the frontend Batch-2 slices, the rootshard/CI sharding engine beyond its
security-relevant inputs, and the release/catalog pipeline beyond confirming the
new reporter is absent from `.github/release-evidence.txt`.

Every finding below was reproduced against the shipped tree before it was
fixed, and every new gate was verified **failing** against the reintroduced
pre-fix shape and passing against the fix.

---

## 1. Executive summary

The findings are one defect class seen four times, in the plane that carries
security alerting off the box, plus one latent nil-dereference in the seam
underneath it.

`internal/alerts.Store.Dispatch` deduplicates on the key `event + ":" + Detail`
within a 30-second window, and on a saturated delivery semaphore it diverts the
payload to a **500-entry** retry queue. Two properties therefore have to hold
for any producer whose firing rate is set by a *fault* rather than by an
operator: the `Detail` must be a **bounded reason class**, so one incident is
one key; and the producer must be **gated on `HasSubscriber`**, because the
default posture is no webhooks configured and the producer sits on the request
goroutine.

`CLAUDE.md` states both rules, and `internal/secscan`'s `remoteScanFail` is the
reference implementation. **Three of the four remaining request-path producers
in the scan plane observed neither rule**, including `clamScanError`, whose own
doc comment says it "mirrors the remote sidecar's `remoteScanFail` model"; a
fourth, `scan_skipped`, kept a bounded Detail but no gate. The
security consequence is not noise: a scanner or CDR fault, combined with
ordinary traffic, floods the bounded retry queue with unsuppressible keys and
**evicts real `threat_detected` alerts** — a security control silenced by a
degradation elsewhere, with no signal that it happened.

The fourth finding is in the seam itself: `alerts.SetSink(nil)` and
`SetSubscriberProbe(nil)` stored a pointer to a *nil function*, so the
`!= nil` pointer guard in `Fire`/`HasSubscriber` passed and the nil function was
then called — a panic on the request goroutine, inside the scan path, in the one
seam whose documented contract is that producers "never need a nil check". It
was found by a test written for finding SEC-ALERTKEY-1 crashing the package.

---

## 2. Findings

### SEC-ALERTKEY-1 — `yara_degraded` mints one alert dedup key per regex match — **Medium**

**Files:** `internal/yara/yara.go` (`yaraSaturationCheck`, `yaraDegradedCheck`).

**Defect.** Both producers built the alert `Detail` with
`fmt.Sprintf(... "inflight=%d max=%d" ...)` over the **live** in-flight counter.
The number the message reports is the number that changes, so the dedup key was
distinct **by construction**, not merely often — dedup could not suppress this
producer at all. Neither was gated on `HasSubscriber`, and `alert_degraded`
defaults to **true**.

**Reachability.** `matchRegex` (`internal/yara/regexrunner.go`) evaluates
saturation **once per string definition per scanned body**, deliberately — the
cap governs concurrent regex work. So a rule set with N regex strings fans N
dispatches out of one scanned response. The approaching-saturation arm fires for
every match while in-flight sits in `[0.8·cap, cap)` (default cap 50, so from 40
in-flight); the saturated arm fires for every match at or above the cap.

**Attack scenario.** An unauthenticated client that can put scannable content
through the proxy drives concurrent YARA regex work — a slow or
catastrophically-backtracking pattern in the operator's own rule set makes this
cheap, since an abandoned match inherits its in-flight charge for the full
per-string budget. Once in-flight crosses 40, every subsequent match spawns a
goroutine, builds a payload, formats an RFC3339 timestamp and takes the
**process-wide** dedup mutex — the serialisation point every other alert
producer in the process also queues on — inserting a key that can never be
deduplicated. The dedup map is driven to `maxDedupEntries` (its CHAOS-27 cap),
charging `dedupEvicted` and amortised O(len) prune scans under that same mutex.
With webhooks configured, each key is a delivery, and on a saturated semaphore a
retry-queue entry — evicting genuine `threat_detected` alerts from a 500-entry
queue.

The producer therefore degrades the node hardest exactly while the node is
already degraded, and its worst effect is to **suppress the alerting of real
threats**.

**Preconditions.** YARA enabled with at least one regex string (a normal SWG
posture); `alert_degraded` at its default `true`.
**Exploitability:** low skill, no credentials, no network position.
**Likelihood:** high once YARA is deployed — reachable without an attacker at
all, by ordinary load.
**Impact:** availability of the proxy's request path plus **integrity of the
security-alerting channel**.
**Affected assets:** the alert retry queue and dedup map, the process-wide alert
mutex, the request goroutine.
**CWE:** CWE-779 (excessive logging/alerting of security events), CWE-770
(allocation without limits), contributing to CWE-778 (insufficient logging of
the events that matter).
**OWASP:** A09:2021 Security Logging and Monitoring Failures.
**Severity:** Medium. **Regression risk of the fix:** low — the change is to the
alert payload and the log gate; the saturation verdict matrix is unchanged and
pinned by a control.

**Fix.** Bounded classes `saturated` / `approaching_saturation`; a
`HasSubscriber` gate through the `alerts` seam; the numbers moved to a
rate-limited log line (≤1 per 30 s, **separate gates per state**, per
`storage_health.go`'s rule that two failures must not share a rate gate) and to
a new `yaraSaturationSkips` counter surfaced as `yara_saturation_skips` on the
scan-status surface beside the existing `yara_match_panics`.

---

### SEC-ALERTKEY-2 — `scan_clam_error` carries the raw ClamAV error — **Low-Medium**

**Files:** `internal/secscan/secscan.go` (`clamScanError`, `recordClamFailure`).

**Defect.** `Detail: err.Error()`, ungated. Every error `internal/clamav`
produces wraps a `*net.OpError` whose text embeds the **ephemeral local port**
(`read tcp 127.0.0.1:54012->127.0.0.1:3310: connection reset by peer`), or a
**daemon-supplied response string** (`clamav: scan error: %s`,
`clamav: unexpected response: %q`). One dark daemon therefore produced one
distinct dedup key per proxied response. The `obs.Printf` beside it was likewise
unbounded — one line per failing response, into a sink that **blocks** its
producer on a full queue (`internal/logsink`).

This is the defect `remoteScanFail` documents at length one file over, and
`clamScanError`'s own comment claims to mirror it.

**Severity:** Low-Medium (same mechanism as SEC-ALERTKEY-1 but one dispatch per
response rather than per regex string, and it needs the daemon to be unwell).
**CWE:** CWE-779, CWE-770. **OWASP:** A09:2021.

**Fix.** `clamFailureClass` maps this package's **own** error prefixes to a
fixed class set (`connect_failed`, `write_failed`, `read_failed`,
`empty_response`, `protocol_error`, `daemon_scan_error`, `scan_aborted`), with
any unrecognised shape folding to `engine_error` — the fold is the load-bearing
part. `HasSubscriber` gate added; the cause moved into one rate-limited log line
that also **sanitises** it (the daemon writes part of that text), with the
magnitude on the existing `culvert_clamav_scan_errors_total`.

---

### SEC-ALERTKEY-3 — `cdr_unavailable` lets the remote end choose this node's dedup keys — **Low-Medium**

**Files:** `cdr_proxy.go` (`cdrHandleCallError`, new `noteCDRCallError`).

**Defect.** `Detail: fmt.Sprintf("sluice call failed: %v", err)`, ungated,
once per inspected response body whose Sanitize call failed. A gRPC transport
error embeds the ephemeral local port; a **server-produced** status embeds a
description written by Sluice. So a compromised, buggy or merely chatty sidecar
could mint an unbounded key space in this node's alert store — the dedup key is
attacker- or peer-chosen, not merely variable.

The log line was `logger.Printf("CDR: call error: %v", err)` — **raw**, with no
`sanitizeLog`. A status description containing a newline forges a second process
log record; the process log is the forensic record (`internal/logsink` drains it
to the rotating file and the syslog SIEM forwarder carries it). The adjacent
oversize line had the same shape.

**Severity:** Low-Medium. **CWE:** CWE-779, CWE-770, and **CWE-117** (improper
output neutralization for logs) for the raw `%v`. **OWASP:** A09:2021.

**Fix.** `cdrCallErrorClass` returns the gRPC `codes.Code` string — fixed
cardinality by protocol — and folds a non-status error to `unknown`;
`HasSubscriber` gate; one rate-limited log line carrying the **sanitised** cause
and the existing `culvert_cdr_errors_total` magnitude (no second counter, no
second dialect). The oversize line is sanitised too.

---

### SEC-ALERTKEY-4 — `scan_skipped` fires ungated on a traffic-driven path — **Low**

**Files:** `security_scan.go` (`logScanLimitExceeded`).

**Defect.** The `Detail` was already bounded (a constant limit), so the dedup
window does suppress the *deliveries* — but the producer was ungated, and the
gate's whole point is the work done **before** the window is consulted: a
goroutine, a payload build, an RFC3339 format and the process-wide dedup mutex.

`CLAUDE.md` exempts producers "whose rate is bounded by construction (a
multi-second scan timeout, a disk-full transition, a lockout)". This one is not
among them: **an origin chooses its own response size**, so every response over
the scan limit takes this path, and that rate is set by traffic. It is also the
path on which content is forwarded **unscanned**, so the volume peaks exactly
when the operator most wants the node responsive.

**Severity:** Low (no key explosion, so no retry-queue eviction — cost only).
**CWE:** CWE-770. **OWASP:** A09:2021.

**Fix.** `HasSubscriber` gate, with the counter (`secscan.AddScanSkipped`) left
strictly ahead of it and pinned by a control, so the unscanned-content signal is
unchanged on a node with no webhooks.

---

### SEC-ALERTSEAM-1 — a nil install panics the producer instead of uninstalling — **Low**

**Files:** `internal/alerts/alerts.go` (`SetSink`, `Fire`, `SetSubscriberProbe`,
`HasSubscriber`).

**Defect.** `func SetSink(fn Sink) { sink.Store(&fn) }` stores a pointer to a
nil function value when `fn` is nil. `Fire`'s guard is `if s := sink.Load(); s != nil`
— which passes — and `(*s)(event, p)` then calls a nil func and **panics**. The
probe is identical. The package doc promises the opposite in both directions:
`Fire` "is a no-op when no sink is installed … so producers never need a nil
check", and `HasSubscriber` "fails toward DELIVERY … so a missing probe can
never silence a real alert".

`HasSubscriber` is called **synchronously on the request goroutine** by
`remoteScanFail`, `clamScanError` and (now) `fireYARADegraded`, so the panic
lands inside the scan path of an in-line security gateway.

**Reachability today:** no production call site passes nil (`alerts.go` installs
both in `init`), so this is a **latent** defect and a contract violation rather
than a live bug — it is fixed because the seam's whole purpose is that producers
need no nil check, and because the gating work above adds call sites to it.
**CWE:** CWE-476 (NULL pointer dereference), CWE-248 (uncaught exception).
**Severity:** Low. **Regression risk:** none — a real install is unchanged, and
a control pins that.

**Fix.** A nil install **uninstalls** (stores a nil pointer); the guards also
check the function value.

---

## 3. What was reviewed and found sound

**`cmd/cireport` + `ci-perf-report.yml` (PR #1477).** This is a `workflow_run`
consumer, the classic GitHub Actions privilege-escalation shape, and it holds
up:

- Workflow-level `permissions: actions: read, contents: read`, no job-level
  widening, no `pages:`/`pull-requests:` write anywhere.
- Both jobs pin `ref: ${{ github.event.repository.default_branch }}` with
  `persist-credentials: false`, so a `--ref <branch>` dispatch cannot run an
  unreviewed collector; `run-report` additionally excludes
  `workflow_run.event == 'pull_request'`.
- `RUN_ID`/`RUN_ATTEMPT` are validated numeric in shell before interpolation;
  the one value written to `$GITHUB_ENV` is a JSON number from the collector's
  own report.
- Artifacts are read as **data**: downloaded into memory, an allowlist of
  member **base names** decoded (`readableArtifacts`; `qa-race-build`, which
  carries the prebuilt test binary, is deliberately absent), nothing extracted
  to disk, so zip-slip is structurally absent. Sizes are bounded at the API
  claim *and* at the read (`maxArtifactBytes`, `maxMemberBytes`, `LimitReader`
  with a `limit+1` probe), and `f.UncompressedSize64` is checked before the
  member is opened.
- `redactURLError` strips the query from transport errors, which matters
  because an artifact download redirects to presigned storage whose query *is*
  the credential and the error text reaches reports readable by anyone with
  repository read.
- Trust of retained reports is explicit and correct (`trustedReport`): artifact
  **names are not access-controlled**, so the producing run is resolved through
  the API and required to be the reporter workflow, on the default branch, in
  this repository, from an event that runs default-branch code; then the
  report's self-declared run identity is compared field-for-field with the API.
  A PR cannot make a failed equivalence audit read as passed.
- Run **titles** are trusted only for `workflow_dispatch` — a pull request's
  `display_title` is its author's PR title, and `analyze_test.go` pins that a PR
  named `audit=true fault=classifier-fails` declares nothing.
- The reporter is absent from `.github/release-evidence.txt` and from branch
  protection, so nothing it computes can gate a release.

**Test-wall edits in the same PR** (`security_race_ownership_test.go`,
`qa_race_shards_test.go`) **strengthen** their assertions; the ownership matrix
expectations are unchanged and only their recorded rationale was updated.

**`restore.go`** (`readTarballLimited`, stage 6A): behaviour-preserving. Check
order, the absolute-path guard, the `..` guard, the duplicate-entry guard and
the `data/` namespace guard are unchanged; the declared-size bounds are the same
constants, now passed in so kilobyte fixtures can drive the real parser.

**`rootca_recovery.go` / `ca_metrics.go` / `ui_security.go`** (PR #1440): the
load-failure latch now clears inside the recovery record's locked transition —
a consistency fix on a surface an operator acts on. No posture change.

**Structural gates executed on the unmodified tree** (all green): route
metadata parity and enforcement (C1, C1.5, C2, C2c, C4), the D0 baseline, the
`configSurfaces` registry wall, the SOCKS5 destination-sink and
log-sanitisation walls, the release-identity SSOT, and the redaction/traversal
walls.

---

## 4. Residual risk

- **Reviewed-but-unbounded elsewhere.** The sweep covered request-path
  producers. `decryption_autoexclude_surge` interpolates a count into its
  `Detail`, but its rate is bounded by the surge window, so it is left as is —
  the rule is *rate set by a fault*, not *any varying Detail*.
- **Left open, not in this change's scope.** `readTarballLimited` bounds
  declared **bytes** per entry and in aggregate, but nothing bounds the **number
  of entries**: a gzip-compressed tar of many zero-size `data/*` headers adds an
  unbounded map entry and slice element each while contributing nothing to
  `totalDeclared`. The amplification is ~10–100× of an operator-supplied archive
  file, and restore is an operator CLI action on a file already in the backup
  volume, so this is recorded rather than fixed. It is the same reasoning the
  aggregate bound was added under (Codex, PR #1344), applied to the axis that
  bound does not cover.
- **`.github/release-evidence.txt`'s NOT-APPLICABLE comment block** still names
  `publish-catalog-pages.yml` and `verify-dual-publish.yml`, which were deleted
  when GitHub Pages was retired as a catalog origin, and does not name
  `verify-catalog-publish.yml` or `ci-perf-report.yml`. Comment drift only — the
  enforced rows are correct and `TestCIPerf_NotReleaseEvidence` pins the
  reporter's absence — but a manifest whose prose disagrees with the tree is the
  kind of thing a later reader trusts.
- **Lint could not be run locally**: the installed `golangci-lint` is built
  against Go 1.25 and this module requires 1.26, so it panics in the type
  checker. `go build`, `go vet` and `gofmt` are clean; CI runs its own pinned
  version.

---

## 5. Tests

New gates, every defect gate verified failing against its reintroduced pre-fix
shape:

| File | Gates | Covers |
|---|---|---|
| `internal/yara/yara_degraded_alert_test.go` | 9 | bounded Detail across 60 in-flight/cap values; no digits in the key; subscriber gate; **fail-safe** when no probe is installed; `alert_degraded=false` still silent; **control** — the saturation verdict matrix (fail-closed / fail-open, at, above and below the cap) is unchanged; exact skip counter under 8×50 concurrent calls; rate-gate onset/suppression/recovery; separate gates per state |
| `internal/secscan/clam_alert_bound_test.go` | 5 | one key across 200 ephemeral ports; every error shape `internal/clamav` produces, plus nil, an unknown shape, an **embedded-prefix imitation** and newline-bearing text, each landing in the declared set; subscriber gate with a **control** that the counter still moves; exact counter under 8×40 concurrent calls; end-to-end Detail is the class |
| `cdr_alert_bound_test.go` | 7 | one key across 200 ephemeral ports **and** 200 server-worded descriptions; the class is the gRPC code, with non-status and nil folding; no remote text or newline in the key; subscriber gate with a **positive control alert** so the negative means something; a subscribed outage collapses to one key (waiting for **all** dispatches — reading after the first passes the unbounded shape by luck); **control** — oversize still skips and a transport fault is still counted and routed through `fail_mode` |
| `proxy_scan_limit_signal_test.go` (appended) | 1 | `scan_skipped` gated with **no subscriber** while the counter still moves 20/20, a positive **control alert** so the negative means something, and one dedup key while subscribed; observed at the alerts SINK, because this producer fires through the internal seam whose sink was captured by value at init |
| `internal/alerts/seam_nil_test.go` | 4 | nil sink is a no-op not a panic; nil probe reads as not-wired and answers true; **control** — a real install still dispatches and decides per event; concurrent install/replace against live producers under `-race` |

Existing `internal/secscan/clam_error_test.go` was updated to the bounded-class
contract: its per-invocation marker lived in the alert `Detail`, which is now a
class, so the exact synchronous counter delta is the proof that *this*
invocation fired and the alert assertions are stated over the class (which holds
for a straggler goroutine from another invocation too).

`docs/operator/mcp-first-controlled-canary-review.md` §25d's scanned-file count
moves 2,602 → 2,606 for the four new files, as
`TestCredWall_LedgerStatesTheRealScanCount` requires.

**Run:** `go build ./...`, `go vet ./...`, `gofmt -l` clean;
`go test -race ./internal/yara ./internal/secscan ./internal/alerts` green; the
root package's CDR / alert / scan / YARA / ClamAV / security selection green.
