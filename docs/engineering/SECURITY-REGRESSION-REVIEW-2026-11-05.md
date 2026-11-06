# Security Regression Review — 2026-11-05

**Scope.** `2d03196…ee0f2ab` (`origin/main`) — the 24 h since the 2026-11-04
review, 5 merged pull requests (#1802 #1803 #1804 #1805 #1806), 25 files,
+3,314/−50. Seven production files changed: `internal/secscan/secscan.go`,
`internal/scanner/scanner.go`, the new `internal/scanner/inflight.go`,
`scanner.go`, `security_scan.go`, `ui_security_decompress.go` and
`static/index.html`, plus `go.mod`, three CI workflows, one string-only
diagnostics change and ~1,400 lines of new tests.

| PR | Change | Security surface |
|---|---|---|
| **#1803** | `fix(scanner): bound, count and guard the DPI scan worker (CHAOS-110)` — new in-flight gate, panic containment, status rows, GUI tiles | **DPI fail-closed posture**, DoS/memory exhaustion, availability, panic containment, admin disclosure |
| **#1806** | `perf(secscan): pool the scan-path gzip and deflate decoders` | **cross-response data retention on the scan path**, decompression-bomb refusal, scan-coverage equivalence |
| **#1802** | `security(godebug): pin the x509 trust-store default a dependency bump flipped` + `godebug_pins_test.go` | **upstream certificate verification trust anchors** — the fix for 2026-11-04 S-1 |
| **#1804** | `test(godebug): fail when a GODEBUG compatibility entry disappears` | the wall's second direction |
| **#1805** | `diagnostics: warn when a saved decompression ratio limit was refused at load`, scanner/secscan test-ownership fixes | decompression bound visibility, test isolation |

**Question asked.** Not "is the change good?" but the inverse: **did it weaken
the posture that existed 24 h ago?** Every finding is measured against
`2d03196`, not against an ideal.

**Method.** Two of this window's changes can only fail quietly, and they were
read in that direction rather than from their own tests.

The **decoder pooling** is the one that would be a disclosure bug. A pooled
`compress/flate` decompressor keeps a 32 KiB history window between responses,
and on a security web gateway consecutive responses through one pool slot belong
to different users of the same appliance. The committed suite proves the pooled
arm decodes the same bytes as a fresh one and that `release()` drops the
*compressed* buffer; neither is that question. So the question was asked
directly, with a hostile stream rather than a benign one: a raw deflate body
built with `flate.NewWriterDict` back-references **before its own start**, and
`Content-Encoding: deflate` has no dictionary negotiation, so the only bytes
such a body could resolve those references against are the previous response's
plaintext sitting in the window.

The **DPI in-flight gate** is the one that changes a fail-closed decision. It
was measured, not read: how long a refused response actually stalls, whether a
scan that waits and then wins gets a fresh budget, whether slots survive
repeated abandonment, and whether a deployment with no DPI patterns can reach
the new refusal at all.

The **GODEBUG pin** closing 2026-11-04 S-1 was verified by removing it.

**Five hypotheses were formed against the window's own claims. Four were
disproved; one survived, and a second claim was found to be inaccurate.**

1. *A hostile deflate or gzip body can read a previous response's plaintext out
   of the pooled decoder's retained 32 KiB history window.* **Disproved
   empirically, 200 interleaved rounds at `GOMAXPROCS=1`, both arms, zero
   leaks.* The protection is real but it is **not in this repository**:
   `compress/flate` rejects a back-reference with
   `dist > f.dict.histSize()` as `CorruptInputError`, and `histSize()` returns
   `wrPos` — the bytes *this* stream has written — whenever the window is not
   yet `full`. `Reset(r, nil)` re-runs `dictDecoder.init`, which reuses the
   `hist` array but zeroes `wrPos` and `full`, so every stream starts with a
   logically empty history even though the stale bytes are still physically
   present. The gzip arm is doubly covered: a dict-referencing payload also
   fails the CRC. Both end in `expansionVerdict`'s `readErr` branch, which
   returns the original compressed bytes — the pre-pool fallback, unchanged.
   Because that guarantee lives in the toolchain rather than here, it is now
   pinned by `internal/secscan/decompress_pool_leak_test.go` instead of being
   reasoned about; a vendoring or toolchain change that relaxed it would
   otherwise be silent.
2. *The pooled gzip reader retains the origin-supplied `FNAME`/`FCOMMENT`
   strings of the response it just expanded, parking origin-chosen bytes in a
   pool slot once per core.* **Disproved, and the premise was wrong twice.**
   `gzip.Reader.Reset` assigns a whole fresh `Reader` value before reading the
   new header, so `Header` is zeroed regardless of whether that read then
   succeeds; and the exposure was bounded anyway, because `readString` returns
   `ErrHeader` past the 512-byte `z.buf` scratch, so a header string can never
   exceed 512 bytes. Pinned by the second test in the same file.
3. *The pooling change moves a decompression-bomb refusal, a truncation, or a
   malformed-stream fallback.* **Disproved.** `expansionVerdict` is the single
   shared tail for all four arms and is byte-identical to the pre-change
   sequence; the committed differential oracle runs interleaved repeated rounds
   of six stream shapes (small, window-spanning, empty, header-bearing,
   truncated, not-compressed-at-all) against a frozen pre-pool arm, serially
   and concurrently, and the ratio-refusal path is separately held. The
   deliberate exclusion of brotli is correct and is the right call for the
   stated reason: a brotli ring buffer is sized from the window the **origin**
   declares, so pooling it would hand a hostile response a lever on resident
   memory.
4. *The GODEBUG pin is cosmetic — the `go` line still selects the new default.*
   **Disproved by negative control.** `go list -f '{{.DefaultGODEBUG}}' .`
   reports `x509sslcertoverrideplatform=0` with the pin and **empty** with the
   line deleted, so the pin is load-bearing and 2026-11-04 S-1 is genuinely
   closed. The wall is two-sided and runs in the default root suite (no build
   tag), with negative controls for an appearing entry, a disappearing entry, a
   dropped pin, a changed value and a language bump. The one Go 1.27 default
   left adopted rather than pinned, `tracebacklabels`, is recorded with its
   rationale, and that rationale checks out: no non-test file in this tree sets
   goroutine labels (`grep -rn pprof --include=*.go` outside tests: no hits), so
   there is nothing for the new traceback format to disclose.
5. *The new DPI in-flight gate fails closed, so it cannot have made anything
   worse.* **This is S-1.** Failing closed is the right posture and is not in
   question. What the gate also does is give every response that arrives at a
   full gate a **non-cancellable 5-second stall before that refusal**, and the
   gate has no operator control of any kind.

---

## 1. Executive summary

**No authentication, authorization, policy-precedence, session, CSRF, XSS,
SSRF, audit, secrets, TLS, request/response-processing or persistence
regression was introduced in this window.** The two changes that could have
moved a security decision quietly did not: the pooled scan-path decompressors
cannot leak a prior response's plaintext or alter a bomb refusal, and the
GODEBUG pin verifiably restores the trust-anchor default that 2026-11-04 found
flipped by a dependency bump. The new DPI panic containment is a strict
improvement — before it, an unrecovered panic inside an uninterruptible regex
match terminated an in-line gateway, and root's `safeDPIScan` could not catch it
because its `recover()` runs on the wrong goroutine.

The window's one finding is in the shape of the new fail-closed path rather than
its direction. Bounding the DPI scan worker was necessary and the measurements
behind it are sound; the cost is that a saturated engine now holds each arriving
response for a full `dpiRegexTimeout` (**5 s**, a compile-time constant) and then
blocks it uninspected, with no operator setting for the cap, the wait, or the
posture — where the twin YARA engine has all three. A second, smaller defect is
in the lead indicator meant to warn the operator before that starts happening:
it fires at no load on the smallest gate, which is the one shape where it most
needs to be believed.

| ID | Finding | Severity | Regression risk | Status |
|---|---|---|---|---|
| **S-1** | The DPI gate's refusal costs a non-cancellable 5 s stall per response and has no operator control of cap, wait or posture | **Low** | In-window; availability only, direction is fail-closed | **Reported** (no behaviour change made) |
| **S-2** | `approachingCheck` truncates 80% down, so the two-slot gate a 1-vCPU container gets warns "approaching saturation" on one ordinary scan — permanently | **Low** | In-window; disables the lead indicator for S-1 by crying wolf | **Fixed in this branch** |
| **S-3** | `secScanStatusMap`'s new comment claims a role-gated surface; the optional scan sidecar serves the same map unauthenticated | **Informational** | In-window comment, pre-existing surface | **Comment corrected in this branch** |
| **S-4** | Pooled-decoder cross-response leakage is prevented by `compress/flate`, not by this repository, and nothing here pinned it | **Informational** | Pre-existing-by-construction; created by this window's pooling | **Test added in this branch** |

---

## 2. Security findings

### S-1 — The DPI gate's refusal is a 5-second stall, and the gate has no operator control

**Severity: Low. CWE-400 (uncontrolled resource consumption), CWE-770
(allocation without limits or throttling — here, time), CWE-1088 (synchronous
access of remote resource without timeout control). OWASP A04:2021 Insecure
Design, A05:2021 Security Misconfiguration. Regression risk: in-window,
availability only — the verdict direction is fail-closed and correct.**

**What changed.** `patternSet.scan` now books a slot before spawning its
worker, and on failure to get one it refuses:

```go
slot, admitted := acquireSlot(budget)
if !admitted {
	// S17: the content was never inspected, so it is not known clean.
	return SaturatedReason, true
}
```

`acquireSlot(wait)` tries a non-blocking send, then waits on a timer for the
full `wait`. The `wait` passed is `budget`, which is `dpiRegexTimeout` — and
that is `const dpiRegexTimeout = 5 * time.Second` (`internal/scanner/scanner.go:358`),
not a setting. The cap is `defaultMaxInflight()` = `2 × GOMAXPROCS(0)`, floor 2.
`SetMaxInflight` is exported but, as its own comment says, "production uses
`defaultMaxInflight`" — nothing calls it outside tests.

**Measured, not inferred** (`internal/scanner/inflight_cost_test.go`, added in
this branch, cap 1, budget 120 ms):

```
refused clean content after a 121ms stall (budget 120ms)
wait-then-win total 60ms (ceiling is wait+budget = 240ms)
```

So a refusal costs the **whole** wait, and a scan that waits and then wins a
slot is handed a *fresh* budget — `st.startedAt` is stamped and a new
`time.NewTimer(budget)` is armed after admission. At production values the
worst-case non-cancellable duration of a single DPI scan therefore rose from
`budget` to **`budget` + `budget` = 10 s**, and a refusal that was previously
impossible now costs 5 s.

**Attack scenario.** An actor needs `2 × GOMAXPROCS` concurrent inspected
responses whose bodies make an operator-configured DPI pattern run long — a
large text body against a pattern with superlinear backtracking is the ordinary
way, and `MaxBytes` is the only bound on the body. On a 4-vCPU node that is
**8 concurrent requests**. While those 8 hold slots, every other inspected
response on the node stalls 5 s and is then served a 403
"Blocked by content inspection policy" without being inspected. The stalled
request holds its proxy goroutine and keeps its buffered response body reachable
for the whole 5 s, so the stall is also a memory-residency multiplier: 1,000
concurrent inspected responses at a 5 MiB scan window hold up to ~5 GiB for 5 s
that they would previously have released promptly.

**Preconditions and exploitability.** Requires DPI patterns to be configured at
all — a gateway with none never reaches the gate, because
`ContentScanner.Scan` returns on `len(ps.compiled) == 0` before `acquireSlot`
(pinned by `TestChaos110_NoSlotTakenWithoutPatterns`). Requires the ability to
drive `2 × GOMAXPROCS` concurrent inspected responses, which for a forward proxy
is any authorized client. No authentication bypass, no data disclosure, no
policy change: **the gateway blocks, it does not pass**. **Likelihood: Medium
for accidental (a busy node with slow patterns), Low for deliberate (the payoff
is self-denial of service).** **Impact: availability of inspected traffic for
all users of the node.**

**Honest framing, because the inverse was also measured by the change's own
authors and is in `inflight.go`:** before this gate, the abandoned-worker
population was unbounded, and at concurrency 32 their baseline blocked 32 of 32
clean bodies — a feedback loop where each block made the next scan slower. The
gate breaks that loop. This finding is **not** that the cap was wrong. It is
that three decisions inside it are hard-coded where the twin engine makes all
three operator-visible: `internal/yara` has a configurable in-flight maximum
(`yara_inflight_max` is a setting), a configurable timeout
(`yara_timeout_secs`), and an admin-selected on-timeout posture
(`yara_on_timeout`). The DPI engine now has an equivalent fail-closed cliff with
none of them, and `AGENTS.md`'s own rule is that a new operator-relevant
behaviour needs API and UI parity or a recorded deferral. The window delivered
the observability half (`dpi_inflight`, `dpi_inflight_max`,
`dpi_saturation_blocks`, `dpi_abandoned_workers`, `dpi_match_panics`, with GUI
tiles) and deferred the control half without recording the deferral.

**Recommended fix** — reported, not applied, because every option below changes
a deliberate fail-closed decision and that is the owner's call, not a
regression-review call:

1. **Decouple the wait from the match budget.** The wait is currently `budget`
   only because that is the value in scope. A slot comes free as fast as the
   *shortest* in-flight match, not the longest permitted one, so a wait of
   `budget/10` (500 ms) would admit essentially every scan that the 5 s wait
   admits while cutting the refusal stall tenfold. This is the smallest change
   with the largest effect and does not weaken the refusal.
2. **Surface the cap as an operator setting** (`dpi_inflight_max`), mirroring
   `yaraGetMaxInflight`, through `SetMaxInflight` — which already exists as
   exactly that seam, with generation-safe resize already tested. Add the admin
   API endpoint and the UI control for parity with the tiles already shipped.
3. **Record the posture deferral** if an on-saturation posture (block vs.
   pass-with-audit) is deliberately *not* being offered, so "DPI always fails
   closed at the cap while YARA's posture is selectable" is a documented
   asymmetry rather than an accident.

**Required tests** for whichever is taken: the stall ceiling under a full gate
(the shape of `TestChaos110_SaturationStallIsWaitPlusBudget`); a boundary test
that the wait change does not turn a would-be-admitted scan into a refusal
(release a holder just inside and just outside the new wait); a concurrency test
that the cap holds across a live resize (`TestChaos110_ResizeKeepsOldHolders…`
already covers the generation half); an authorization test that any new endpoint
carries handler-level `requireRole(RoleAdmin)` and audits before
`saveConfigVersion`; and a negative control that a gateway with no DPI patterns
still never refuses.

**Files.** `internal/scanner/inflight.go`, `internal/scanner/scanner.go:356-414`,
`security_scan.go:364-392`, `static/index.html` (tiles).

---

### S-2 — The saturation lead indicator fires at no load on the smallest gate (fixed)

**Severity: Low. CWE-1121 (excessive use of unconditional branching → here, an
unconditional warning), effectively CWE-778-adjacent: insufficient *useful*
logging, by dilution. OWASP A09:2021 Security Logging and Monitoring Failures.
Regression risk: in-window.**

**What was wrong.**

```go
if limit <= 0 || n < int64(limit*80/100) {
	return
}
```

`limit*80/100` truncates. The gate's floor is `inflightFloor = 2`, which is what
a `GOMAXPROCS=1` container gets — a very common sidecar shape, and exactly the
shape `defaultMaxInflight` exists to serve. For `limit == 2` the threshold is
`2*80/100 == 1`: **one ordinary scan**. Reproduced directly in the probe output
before the fix:

```
WARN DPI: approaching saturation: 1 of 2 in-flight scan workers
```

So a single-vCPU node emits "approaching saturation" every
`saturationLogInterval` (10 s) forever, at zero load. That is the worst failure
this particular line can have, because it is the lead indicator for S-1's
refusal: an operator who learns it means nothing loses the only warning they get
before clean content starts being blocked uninspected — and
`dpi_saturation_blocks`, the counter that would tell them it has started, is on
a role-gated page they have no reason to open.

**Fix applied in this branch.** Round the 80% threshold **up**, clamped to the
cap:

```go
func approachingThreshold(limit int) int64 {
	if limit <= 0 {
		return 0
	}
	t := int64((limit*80 + 99) / 100)
	if t > int64(limit) {
		t = int64(limit)
	}
	return t
}
```

`1→1`, `2→2`, `3→3`, `4→4`, `8→7`, `16→13`, `64→52`. The two- and three-slot
gates now warn only at the cap, which is the honest threshold when there is no
lead time to be had; every larger gate keeps its lead. Strictly more
conservative than the previous form in every case, so it cannot introduce a new
warning anywhere. No security behaviour changes: this is a log trigger.

**Tests added.** `TestChaos110_ApproachingThresholdDoesNotFireOnOneOrdinaryScan`
— the full threshold table including the `limit <= 0` boundary, an assertion
that the threshold never exceeds the cap, and a negative control that asserts
the old truncating form produced the `1` this test exists to reject (so the test
fails if someone reverts the arithmetic).

**Files.** `internal/scanner/inflight.go`, `internal/scanner/inflight_cost_test.go`.

---

### S-3 — A new comment claims a role-gated surface the sidecar does not gate (corrected)

**Severity: Informational. CWE-497 (exposure of system data to unauthorized
control sphere). OWASP A01:2021 Broken Access Control. Regression risk:
in-window comment; the surface itself is pre-existing and opt-in.**

The new `dpi_*` rows were added to `secScanStatusMap` under:

> `// is sized against. Role-gated surface, so the magnitudes are safe here;`

That is true of one of the three callers and not of the others.
`apiSecScanStatus` (`ui_security.go:783`) does carry
`requireRole(w, r, RoleViewer)`. But `ScanService.handleStatus`
(`scan_svc.go:276`) serves **the same map** with no role check at all, on its
own listener:

```go
mux.HandleFunc("/scan", ss.handleScan)
mux.HandleFunc("/health", ss.handleHealth)
mux.HandleFunc("/status", ss.handleStatus)
```

This is not a new exposure and not, by itself, a defect: the sidecar is opt-in
(`-scan-svc-listen` / `scan_svc.listen`, off by default), its own header
documents it as reachable by "any other process on the same host/network", and
the `yara_*` in-flight magnitudes it now sits beside have been on that surface
since Tier 1.3. What is a defect is a comment that tells the next reader the
trust boundary is somewhere it is not — in a file where the next reader's
question will be "may I put this value here?".

**Fix applied in this branch:** the comment now names both surfaces and the
condition under which the unauthenticated one exists. No behaviour change — in
particular, **no role check was added to the sidecar**, because that would
change a documented, deliberate, opt-in trust model and is outside a regression
review's scope. If the owner wants that boundary tightened it is its own change,
with its own compatibility analysis for existing sidecar deployments.

**Files.** `security_scan.go:376-392`.

---

### S-4 — The pooled decoders' safety rests on a toolchain guarantee nothing pinned (test added)

**Severity: Informational. CWE-226 (sensitive information in reused resource),
CWE-200 (exposure of sensitive information). OWASP A01:2021 Broken Access
Control. Regression risk: created by this window's pooling; no live defect.**

Hypothesis 1 is disproved — there is no leak today. But the reason there is no
leak is `compress/flate`'s `dist > f.dict.histSize()` check and the fact that
`dictDecoder.init` zeroes `wrPos`/`full` while reusing the `hist` array. Both are
standard-library internals. This repository's own argument for the pool, in the
`WHY THE SOURCE READER IS OWNED` comment, correctly addresses retention of the
*compressed* buffer and says nothing about the decompressed history window,
because nothing here has to — until a toolchain or vendoring change makes it
have to, silently.

Before this window there was no window to leak from: each response got a fresh
decoder. After it, "a response cannot read the previous response's plaintext" is
a security property of the scan path with no test naming it.

**Test added in this branch**: `internal/secscan/decompress_pool_leak_test.go`
— 200 interleaved rounds at `GOMAXPROCS=1` priming a 20 KiB canary through the
pooled gzip and deflate arms and then feeding each a `flate.NewWriterDict`
stream whose back-references reach before its own start (plus the gzip-enveloped
variant), asserting the canary never appears in any returned expansion; and the
header-state control, asserting a drained pool holds no origin-supplied
`Name`/`Comment`/`Extra` and no source bytes.

---

## 3. Regression analysis — what was checked and found unchanged

- **Decompression-bomb refusal (fail-closed).** `expansionVerdict` preserves the
  exact pre-change order: ratio refusal → `nil, true`; read error → original
  bytes; empty expansion → original bytes; otherwise the expansion. The flat
  `MaxDecompressBytes` ceiling still truncates rather than refusing, and the
  ratio ceiling still probes one byte past to distinguish "exactly the limit"
  from "there was more". `readCapped` allocates its own buffer, so no returned
  expansion aliases pooled decoder state — the one aliasing bug that would have
  survived every behavioural test.
- **No slot leak, no over-admission.** `release()` is deferred by the **worker**,
  not the parent, and is the only release; `st.done` is buffered with capacity 1
  and receives exactly one send on every path (verdict, panic, abandoned), so no
  worker can block on it and skip its deferred release. Verified across five
  rounds of deliberate abandonment at the cap: `Inflight()` returns to 0 every
  time, and `AbandonedWorkers()` counts exactly the 10 abandonments.
- **Panic containment is new, and in the fail-closed direction.** `obs.SafeCall`
  wraps the whole pattern walk on the worker goroutine; a contained panic answers
  the parent immediately with `PanicReason, true` rather than letting it wait out
  a budget that will never be met. `matchLoop` returns its verdict instead of
  publishing it, which is what keeps the single-send property above true.
- **No client-visible disclosure from either new reason string.**
  `SaturatedReason` and `PanicReason` reach `logger.Printf("DPI_BLOCKED …
  pattern=%q")` and `recordInspectBlock`; `dpiBlock` writes a fixed
  `"Blocked by content inspection policy"` body. Both are compile-time
  constants, so they add no log-injection surface, and `%q` escapes the
  operator-supplied pattern case that already existed.
- **GUI/API parity and XSS.** The new rows have an API surface, a `uiRoutes`
  entry via the existing `apiSecScanStatus`, and UI tiles. The tiles are written
  with `el.textContent` after `Number()` coercion — no `innerHTML`, no sink.
- **Versioning exclusions respected.** The refused-ratio latch is report-only:
  `applyAdminScanDecompressRatio` still installs the in-range default and still
  logs the refusal, and `scanDecompressRejectedPersisted` never feeds the
  installed bound. `putScanDecompression` is unchanged except for clearing the
  latch on a successful apply; it still audits and persists in the established
  order.
- **Test changes strengthen rather than weaken.** Both in-window test edits add
  assertions: `scanner_timeout_test.go` makes two abandoning tests own their
  worker's whole lifetime (closing a `-shuffle` cross-test miscount), and
  `scan_decompress_setting_test.go` adds the latch to the restore helper plus a
  new positive/negative case for the diagnostics row. No gate was relaxed to
  obtain a pass; no suppression was added to conceal a path. The four new
  `//nolint:errcheck` directives are narrow and explained, on pool-release calls
  whose errors are expected (`io.EOF` on an empty source) or unconditionally nil.

---

## 4. Verification

Commands run at the review SHA (`ee0f2ab`) plus this branch's changes, with the
`go.mod` toolchain (`go1.27.3`):

| Check | Command | Result |
|---|---|---|
| Build | `go build ./...` | exit 0 |
| Changed packages, race | `go test -count=1 -race ./internal/secscan ./internal/scanner` | ok (34.0 s / 8.0 s) |
| Changed packages, race + shuffle | `go test -count=1 -race -shuffle=on ./internal/scanner ./internal/secscan` | ok (8.3 s / 35.2 s) |
| Full root suite | `go test -count=1 -timeout=40m .` | ok, 371.1 s, exit 0 |
| GODEBUG wall | `go test -count=1 -run 'TestGODEBUG_' -v .` | all pass incl. 3 negative controls |
| GODEBUG pin is load-bearing | `go list -f '{{.DefaultGODEBUG}}' .`, with and without the pin | `x509sslcertoverrideplatform=0` / empty |
| Benchgate (incl. the newly registered `internal/secscan`) | `go test -tags benchgate -run 'TestBenchGate_' -count=1 -p 1 -timeout=10m ./internal/secscan ./internal/scanner` | ok, exit 0 |
| Targeted root | `go test -count=1 -run 'TestScanDecompressSetting_\|TestSecScan\|TestDPI\|TestChaos110\|TestGODEBUG_\|TestToolchain' .` | ok |
| `go vet` | `go vet ./internal/scanner ./internal/secscan .` | clean |
| Lint, gate's own command | `golangci-lint v2.15.0 run --new-from-rev origin/main` | 0 issues |
| Lint, changed packages | `golangci-lint run ./internal/scanner/... ./internal/secscan/...` | 0 issues |
| Lint, full tree vs base | `golangci-lint run ./...` on this branch and on stashed base | **identical**: 174 pre-existing issues, same per-linter counts |
| New leak probes | `go test -count=1 -race -run 'TestExpandPooled_\|TestChaos110_' ./internal/secscan ./internal/scanner` | ok |

**Not run, and why.** The E2E suites, the weekly proxy stress job, the
`-race -shuffle` *aggregate* qualification run across every package, CodeQL and
`govulncheck` are hosted gates; this review ran the focused and root equivalents
only. A passing local check is not a passing hosted review or merge gate.

---

## 5. Residual risk

- **S-1 is reported, not fixed.** Until the wait is decoupled from the match
  budget or the cap becomes operator-settable, a node with DPI patterns
  configured and `2 × GOMAXPROCS` slow matches in flight will stall and then
  block other inspected traffic for 5 s per response. The direction is safe; the
  cost is availability. `dpi_saturation_blocks` is the signal, and with S-2 fixed
  the `approaching saturation` line is now a usable precursor to it.
- **The DPI cap is sized from `GOMAXPROCS`, which is sized from the cgroup
  quota.** A deployment that changes its CPU allowance silently changes its DPI
  concurrency cap, and therefore how much concurrent inspected traffic it can
  carry before S-1's cliff. That is the right default and it is not reported
  anywhere except `dpi_inflight_max`.
- **Brotli remains unpooled by design.** Correct; if that is revisited, the
  origin-declared window size is the bound that must be imposed first.
- **S-2 of 2026-11-04 (`uiCustomTLSCorrupt` unsynchronized `bool`) is
  unchanged** — this window added no further reader, but the pre-existing race
  reported on 2026-11-03 and widened on 2026-11-04 is still open.
- **The scan sidecar's `/status` is still unauthenticated** by its own
  documented design, now carrying DPI posture magnitudes alongside the YARA
  ones. Tightening it is a separate change with its own compatibility question.
