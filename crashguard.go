// crashguard.go — M1 panic-recovery (supportability framework).
//
// Design (adversarially synthesized): a single top-level middleware CANNOT catch
// panics in detached relay/geo/alert/SOCKS5 goroutines (Go's recover() only
// unwinds its own goroutine) and MUST NOT try to write an HTTP status after a
// CONNECT hijack. So recovery is split into structural planes plus a per-
// goroutine tap at every detached-goroutine birth site, all funneling into ONE
// re-panic-proof, rate-limited, redaction-aware sink (recordCrash).
//
//   - PROXY plane  = record-only guard (proxyCrashGuard): never touches the
//     ResponseWriter, so the happy path is byte-identical and zero-alloc and a
//     hijacked tunnel is never corrupted. Re-panics http.ErrAbortHandler so
//     net/http keeps its intentional silent-abort protocol.
//   - ADMIN plane  = withAdminPanicRecovery: the admin chain never hijacks, so a
//     clean 500 is valid when nothing was committed. trackedRW implements
//     Unwrap()+Flush() so it is NOT interface-masking (ResponseController + SSE
//     keep working).
//   - Detached go-sites = recoverGoroutine / the relay defer.
//
// The sink logs only crash id/component/correlation (never the raw panic value —
// sanitizeLog scrubs control chars, it does NOT mask a secret), keeps the bounded
// text only in an in-memory lastCrash reachable exclusively via a redacting
// accessor, and is throttled per component so a request-triggered panic cannot
// flood the SIEM or evict the shared audit ring. Timeline note: M1 builds no
// timeline store; the crashRecord is shaped as the enumerated "crash" event so
// the M3 timeline consumes it with no schema change (ADR-0012).
package main

import (
	"fmt"
	"net/http"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/KidCarmi/Culvert/internal/obs"
	"github.com/KidCarmi/Culvert/internal/redaction"
)

// CHAOS-24: publish the crash sink to the internal/* seam so a panic recovered
// inside a leaf-package background worker (feed sync, log drain, health poller)
// lands in the SAME pipeline as a recovered proxy/admin panic — the
// culvert_crash_records_total{component} counter, the system-actor audit entry,
// and the bounded lastCrash record. internal/* cannot import package main
// (ADR-0003), so obs carries the indirection. No correlation ID: a background
// worker has no request context.
func init() {
	obs.SetPanicSink(func(component string, v any) { recordCrash(component, "", v) })
	// CHAOS-120: bind the crash plane's page producer. Assigned HERE rather
	// than as a var initializer because `var crashAlertPage = ...fireAlert...`
	// is an initialization CYCLE the compiler rejects:
	//
	//	fireAlert → recoverGoroutine("alert") → recordCrash →
	//	fireComponentPanicAlert → fireAlert
	//
	// (the cycle runs through whichever name the closure references), and that
	// diagnostic is not an inconvenience to route around — it is the
	// compiler reporting, statically, the same re-entrancy crashAlertSelfExcluded
	// handles at runtime: the alert plane's delivery path is guarded BY the sink
	// that would now page THROUGH it. The indirection is what makes the two
	// planes separable; the exclusion set is what makes the remaining edge safe.
	//
	// Reading fireAlert inside the closure (not capturing it) is also what keeps
	// the documented test-reassignment tolerance: a test that swaps fireAlert to
	// observe the dispatch decision sees this producer's pages too.
	crashAlertPage = func(component string) {
		// The subscriber probe is INSIDE this closure, which only ever runs on a
		// detached goroutine, because it takes globalAlertStore's RWMutex — see
		// fireComponentPanicAlert for why that must never be on the sink's stack.
		if !globalAlertStore.HasSubscriber(alertEventComponentPanic) {
			return
		}
		fireAlert(alertEventComponentPanic, crashAlertPayload(component))
	}
}

const (
	crashMsgMax    = 512  // bound the (attacker-shaped) panic value
	crashStackMax  = 4096 // bound debug.Stack()
	crashCorrIDMax = 128  // bound the client-supplied X-Request-ID correlation id
	// maxCrashLabels is the component-label cardinality cap. It exists for
	// DYNAMIC labels — crashThrottleAllow fails closed past it so a caller that
	// derived a component name from request data cannot grow the throttle map
	// without bound.
	//
	// CHAOS-119 raised it from 32 because Culvert has no dynamic labels and the
	// FIXED set had outgrown the cap. crashRecord.Component calls itself a
	// "fixed enum" and it is: every sink call site passes a compile-time
	// constant or literal, and a source enumeration counted 62 distinct ones
	// (TestCHAOS119_FixedCrashLabelSetFitsTheCardinalityCap, which now holds
	// this invariant and fails when a future round crosses it again).
	//
	// Below the cap, the two overflow behaviours are not equivalent and that is
	// what made 32 a reporting defect rather than a metrics nicety. The counter
	// FOLDS an overflowing label into "other", so the series survives and only
	// attribution is lost; crashThrottleAllow SUPPRESSES it, so the crash
	// record, the crash log line and the system-actor audit entry are never
	// written at all. Slots are first-crash-wins and never pruned, so the 32
	// went to whichever components crashed first — in practice the frequent
	// request-path ones — and the rare, high-severity background rounds that
	// CHAOS-105/116/117/118/119 added were the ones that lost their record.
	// That is exactly inverted from what an operator needs.
	maxCrashLabels     = 128
	crashThrottleEvery = time.Second // min interval per component for the floodable sinks
)

// crashRecord is timeline-shaped, bounded, and redaction-tagged. Summary is the
// only reliably secret-bearing field (recover()'s value can embed a credential)
// so it is masked on export. debug.Stack prints frames/PCs/arg words, never
// string CONTENTS, so it cannot leak a secret string value — still tagged
// sensitive for defense-in-depth. No request bodies/headers, no heap/goroutine dump.
type crashRecord struct {
	ID            string `json:"id"             redact:"public"`
	TS            int64  `json:"ts"             redact:"public"`
	Time          string `json:"time"           redact:"public"`
	Category      string `json:"category"       redact:"public"`    // always "crash"
	Severity      string `json:"severity"       redact:"public"`    // "error"
	Component     string `json:"component"      redact:"public"`    // fixed enum
	CorrelationID string `json:"correlation_id" redact:"public"`    // X-Request-ID if known
	Summary       string `json:"summary"        redact:"sensitive"` // bounded+scrubbed panic text
	Stack         string `json:"stack"          redact:"sensitive"` // bounded+scrubbed debug.Stack
}

var (
	statCrashRecords    int64 // culvert_crash_records_total (unlabeled sum)
	statCrashSuppressed int64 // culvert_crash_records_suppressed_total (throttled)
	statCrashSinkPanics int64 // culvert_crash_sink_panics_total (re-panic swallowed)
	crashByComponent    = newCrashCounter()

	lastCrashMu sync.RWMutex
	lastCrash   *crashRecord // bounded+sanitized (UNMASKED) — export ONLY via lastCrashRedacted

	crashThrottleMu   sync.Mutex
	crashThrottleLast = map[string]int64{} // component -> last heavy-emit UnixNano
)

// recordCrash is the single sink: bound → scrub → meter (always) → [throttle] →
// stack/store/log/audit. It NEVER touches an http.ResponseWriter (safe pre/post-
// hijack, in a detached goroutine, on a raw SOCKS5 conn) and NEVER re-panics (its
// own inner recover), so the sink can never crash the process it protects.
func recordCrash(component, correlationID string, v any) {
	defer func() {
		if recover() != nil { // the sink must never propagate a re-panic
			atomic.AddInt64(&statCrashSinkPanics, 1)
		}
	}()

	// The count metric ALWAYS increments: cheap, lossless, leak-free (fixed
	// component label only, never panic text).
	atomic.AddInt64(&statCrashRecords, 1)
	crashByComponent.record(component)

	// Throttle the expensive + floodable sinks per component so a repeatable
	// request-triggered panic cannot flood the SIEM/disk or evict the shared
	// 500-entry security audit ring (anti-forensics DoS).
	if !crashThrottleAllow(component) {
		atomic.AddInt64(&statCrashSuppressed, 1)
		return
	}

	msg := fmt.Sprint(v) // fmt recovers a panicking Stringer/Error to %!v(PANIC=...)
	if len(msg) > crashMsgMax {
		msg = msg[:crashMsgMax] + "…(truncated)"
	}
	msg = sanitizeLog(msg) // CWE-117 control-char scrub (NOT secret masking)

	// correlationID is the client-supplied X-Request-ID on the admin plane; bound
	// it like the panic value/stack (it is otherwise stored verbatim in lastCrash,
	// the ERROR log, and the audit ring — CWE-770 allocation without limits).
	if len(correlationID) > crashCorrIDMax {
		correlationID = correlationID[:crashCorrIDMax] + "…"
	}

	st := debug.Stack()
	if len(st) > crashStackMax {
		st = st[:crashStackMax]
	}
	stack := sanitizeLog(string(st))

	now := time.Now()
	rec := &crashRecord{
		ID: generateRequestID(), TS: now.UnixMilli(), Time: now.UTC().Format(time.RFC3339),
		Category: "crash", Severity: "error", Component: component,
		CorrelationID: correlationID, Summary: msg, Stack: stack,
	}

	lastCrashMu.Lock()
	lastCrash = rec
	lastCrashMu.Unlock()

	// Local ERROR log: crash id + component + correlation ONLY. The raw panic
	// VALUE is NEVER logged (sanitizeLog scrubs control chars, it does not mask a
	// secret), so panic(cfg.SessionHMAC) must not reach the on-disk/SIEM log.
	logErrorf("PANIC_RECOVERED component=%q crash_id=%s corr=%q",
		component, rec.ID, sanitizeLog(correlationID))

	// System-actor audit entry: Detail carries the crash id only, never panic text.
	auditAdd(AuditEntry{
		TS: rec.TS, Time: now.Format("2006-01-02 15:04:05"), Actor: "system",
		Action: "panic_recovered", Object: component,
		Detail: fmt.Sprintf("crash_id=%s corr=%s (value redacted)", rec.ID, sanitizeLog(correlationID)),
	})

	// CHAOS-120: and the one sink that reaches an operator who is not already
	// looking. LAST, so the durable evidence above is written before anything
	// leaves the box, and so a page can never be the reason a record is missing.
	// See fireComponentPanicAlert for the dedup/secret/termination reasoning.
	fireComponentPanicAlert(component)
}

// crashThrottleAllow is a token-per-interval gate per component. The first hit of
// each component always passes; subsequent hits within crashThrottleEvery are
// gated. The map is bounded to the fixed component set so it cannot grow unbounded.
func crashThrottleAllow(component string) bool {
	now := time.Now().UnixNano()
	crashThrottleMu.Lock()
	defer crashThrottleMu.Unlock()
	last, ok := crashThrottleLast[component]
	// CHAOS-84: MAGNITUDE, not sign. now and last are wall-clock nanos, so a
	// BACKWARD clock step makes the difference negative and a sign-based test
	// keeps returning false for the whole step — recordCrash then returns before
	// updating lastCrash or emitting the stack-bearing log and audit entry, so
	// every same-component crash after the step is lost. Crash evidence is the
	// one record an operator cannot reconstruct, which makes this the sharpest
	// member of the class. Comparing the absolute interval bounds suppression to
	// one window in either direction.
	if ok && time.Duration(now-last).Abs() < crashThrottleEvery {
		return false
	}
	if !ok && len(crashThrottleLast) >= maxCrashLabels {
		return false // flood of dynamic components: fail closed (throttle)
	}
	crashThrottleLast[component] = now
	return true
}

// lastCrashRedacted is the ONLY export accessor: it masks Summary/Stack before the
// record leaves the box (support bundle / health / cloud timeline).
func lastCrashRedacted(rd redaction.Redactor) any {
	lastCrashMu.RLock()
	rec := lastCrash
	lastCrashMu.RUnlock()
	if rec == nil {
		return nil
	}
	return rd.Struct(*rec) // pass by value: a struct, not *struct, for the walk
}

// lastCrashSnapshot returns a copy of the most-recent crash record (bounded,
// UNMASKED text) for a collector to Classify under the bundle redactor, or
// ok=false if no crash has been recorded.
func lastCrashSnapshot() (crashRecord, bool) {
	lastCrashMu.RLock()
	defer lastCrashMu.RUnlock()
	if lastCrash == nil {
		return crashRecord{}, false
	}
	return *lastCrash, true
}

// ── deferred guards (named funcs ⇒ Go open-codes the defer; zero happy-path alloc) ──

// recoverGoroutine is the one-liner for every DETACHED go-site (geo/alert/socks5
// entry). recover() is called directly here, so `defer recoverGoroutine("x")`
// catches correctly.
func recoverGoroutine(component string) {
	if v := recover(); v != nil {
		recordCrash(component, "", v)
	}
}

// runGuarded is the BACKGROUND-WORKER plane (CHAOS-24): it runs one round of a
// long-lived loop under a panic guard and reports whether that round panicked.
//
// It is deliberately per-ROUND, not per-goroutine. Deferring a recover at the
// top of a worker goroutine would let the worker RETURN on panic, converting a
// loud crash into a silent permanent stall — the CA never rotates again, the
// health poller never probes again, the cert never renews again — with the
// process still up and every dashboard green. Guarding the round instead keeps
// the ticker alive, so a transient fault costs one interval and self-heals.
//
// The bool return exists for the fail-closed callers: a worker whose safety
// depends on completing its round (the fencing-lease keepalive) must treat a
// panicking round as a FAILED round, never as a silent success. See
// leaseKeepaliveLoop in ha_lease.go.
//
// It calls recordCrash directly rather than routing through obs so main's crash
// plane stays self-contained (no dependency on sink wiring order at startup).
func runGuarded(component string, fn func()) (panicked bool) {
	defer func() {
		if v := recover(); v != nil {
			panicked = true
			recordCrash(component, "", v)
		}
	}()
	fn()
	return false
}

// proxyCrashGuard is the PROXY plane backstop. RECORD-ONLY — it never writes an
// HTTP status (hijack-safe by construction; the stdlib per-conn recover drops the
// connection). It re-panics http.ErrAbortHandler so net/http keeps its intentional
// silent-abort protocol (used by the ActionDrop HTTP/2 path).
func proxyCrashGuard(correlationID string) {
	if v := recover(); v != nil {
		if v == http.ErrAbortHandler {
			panic(v)
		}
		recordCrash("proxy", correlationID, v)
	}
}

// ── ADMIN plane middleware. The newAdminUIHandler chain never hijacks, so a clean
//    500 is valid. trackedRW tracks commit state AND implements Unwrap()+Flush so
//    it is NOT interface-masking: http.ResponseController and the SSE Flusher path
//    keep working (byte-identical happy path). ──

type trackedRW struct {
	http.ResponseWriter
	wrote bool
}

func (t *trackedRW) WriteHeader(c int)           { t.wrote = true; t.ResponseWriter.WriteHeader(c) }
func (t *trackedRW) Write(b []byte) (int, error) { t.wrote = true; return t.ResponseWriter.Write(b) }
func (t *trackedRW) Unwrap() http.ResponseWriter { return t.ResponseWriter } // http.ResponseController
func (t *trackedRW) Flush() {
	if f, ok := t.ResponseWriter.(http.Flusher); ok {
		f.Flush() // keep SSE (apiEvents) alive
	}
}

func withAdminPanicRecovery(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tw := &trackedRW{ResponseWriter: w}
		defer func() {
			v := recover()
			if v == nil {
				return
			}
			if v == http.ErrAbortHandler {
				panic(v)
			}
			recordCrash("admin", r.Header.Get(headerRequestID), v)
			if !tw.wrote { // never double-commit / never inject into a streamed body
				http.Error(tw.ResponseWriter, "Internal Server Error", http.StatusInternalServerError)
				return
			}
		}()
		next.ServeHTTP(tw, r)
	})
}

// ── capped labeled counter (mirrors the ruleMetrics writePrometheus pattern) ──

type crashCounter struct {
	mu sync.Mutex
	m  map[string]*int64
}

func newCrashCounter() *crashCounter { return &crashCounter{m: map[string]*int64{}} }

func (c *crashCounter) record(label string) {
	c.mu.Lock()
	p := c.m[label]
	if p == nil {
		if len(c.m) >= maxCrashLabels {
			label = "other" // fold overflow; lazily init so it is NEVER a nil-deref
		}
		if p = c.m[label]; p == nil {
			var n int64
			p = &n
			c.m[label] = p
		}
	}
	c.mu.Unlock()
	atomic.AddInt64(p, 1)
}

func (c *crashCounter) writePrometheus(b *strings.Builder) {
	esc := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)
	b.WriteString("# HELP culvert_crash_records_total Recovered panics by component.\n")
	b.WriteString("# TYPE culvert_crash_records_total counter\n")
	c.mu.Lock()
	for label, p := range c.m {
		fmt.Fprintf(b, "culvert_crash_records_total{component=\"%s\"} %d\n",
			esc.Replace(label), atomic.LoadInt64(p))
	}
	c.mu.Unlock()
	b.WriteString("# HELP culvert_crash_records_suppressed_total Crash records throttled by the flood guard.\n")
	b.WriteString("# TYPE culvert_crash_records_suppressed_total counter\n")
	fmt.Fprintf(b, "culvert_crash_records_suppressed_total %d\n", atomic.LoadInt64(&statCrashSuppressed))
	b.WriteString("# HELP culvert_crash_sink_panics_total Panics swallowed inside the crash sink.\n")
	b.WriteString("# TYPE culvert_crash_sink_panics_total counter\n")
	fmt.Fprintf(b, "culvert_crash_sink_panics_total %d\n", atomic.LoadInt64(&statCrashSinkPanics))
}

// resetCrashGuardStateForTest zeroes counters/throttle/last-crash between tests.
func resetCrashGuardStateForTest() {
	atomic.StoreInt64(&statCrashRecords, 0)
	atomic.StoreInt64(&statCrashSuppressed, 0)
	atomic.StoreInt64(&statCrashSinkPanics, 0)
	crashByComponent = newCrashCounter()
	crashThrottleMu.Lock()
	crashThrottleLast = map[string]int64{}
	crashThrottleMu.Unlock()
	lastCrashMu.Lock()
	lastCrash = nil
	lastCrashMu.Unlock()
}

// ── CHAOS-120: the operator-facing page for a CONTAINED panic ────────────────
//
// Everything recordCrash writes above this point is evidence an operator has to
// go LOOKING for: a Prometheus series nobody ships a rule on, an ERROR line in
// a log, one entry in a 500-slot audit ring that the next shuffle may evict, and
// a single-slot lastCrash only a support bundle reads. None of it pages anybody.
//
// That was tolerable while an unrecovered panic killed the process, because the
// process death WAS the page. CHAOS-24/105/116/117/118/119 removed that: every
// detached background round now runs under runGuarded, so a round that panics
// every window keeps the node up, keeps every probe green, and keeps the work
// undone — forever. The threat-feed round that panics on every pass serves
// traffic against frozen intelligence; retryLeadershipResume leaves a node
// HA-gated until someone restarts it. "No alert rule ships on the crash
// counters" is recorded as residual risk by CHAOS-116 (4), CHAOS-117 (5),
// CHAOS-118 (1) and CHAOS-119 (3) — four consecutive rounds of the same family.
//
// CHAOS-25 already decided this question for exactly ONE component. HAState's
// notePanicRound fires ha_sync_panic and says why in its own doc: the counter
// and the alert "are the ONLY operator-facing signal that replication has
// stalled — without them the containment would trade a loud crash for a silent
// one, which is the failure class the guard exists to remove." That reasoning
// was never component-specific. It is generalised here to the sink, so a
// component added by a future round inherits the page instead of needing its
// own; ha_sync_panic stays as the HA plane's narrower, fail-closed-specific page
// (it names the suppressed failover and the manual remedy, which this generic
// event cannot).

// alertEventComponentPanic is the subscribable event for a contained panic in
// ANY component. Subscribable from the Alerts panel (static/index.html) and
// catalogued in internal/alerts/store.go beside the other events.
const alertEventComponentPanic = "component_panic"

// crashAlertDetailComponentMax bounds the component label inside the alert
// Detail. Every sink call site passes a compile-time constant
// (TestCHAOS119_FixedCrashLabelSetFitsTheCardinalityCap enumerates them), so
// this is defence-in-depth against a future dynamic label, not a live need: an
// unbounded label would reach an operator's webhook body and the dedup key.
const crashAlertDetailComponentMax = 64

// crashAlertPage is the page's ENTIRE outbound step — subscriber probe and
// dispatch together — behind one seam, bound in this file's init to a closure
// that reads main's fireAlert at CALL time. See that init for why it is not a
// var initializer, and fireComponentPanicAlert for why everything in it runs on
// a detached goroutine.
var crashAlertPage func(component string)

// crashAlertPageBarrier is a TEST-ONLY seam. Production leaves it nil (one nil
// check, no behavior), mirroring internal/alerts' saveBarrier.
//
// It exists because the page step is detached by design (see
// fireComponentPanicAlert) and reads two package globals — globalAlertStore and,
// through the bound closure, fireAlert. Production assigns both once at startup
// and never again, so there is nothing to race. A TEST that swaps either one to
// observe the dispatch has no happen-before edge to a page goroutine that
// already ran, and `-race` correctly reports the restore as a write racing that
// goroutine's read. A quiescence sleep would paper over that rather than fix it.
//
// The seam is a barrier, not a counter, because the Add side must happen on the
// SINK'S STACK — before the goroutine exists — while the Done side must happen
// inside it: a test sets it to `func() func() { wg.Add(1); return wg.Done }` and
// waits on wg before restoring. There is no window in which a spawned page is
// unaccounted for.
var crashAlertPageBarrier func() func()

// crashAlertSelfExcluded are the components whose own contained panic must NOT
// page, because the page would re-enter the plane that just panicked.
//
// This is a termination argument, not a preference. fireAlert carries
// `defer recoverGoroutine("alert")`, and internal/alerts' retry round runs under
// obs.SafeCall("alerts_retry") whose sink is this one: without the exclusion a
// panicking delivery path would record a crash, which would fire an alert, which
// would panic in the same place, which would record a crash. The per-component
// throttle would bound the RATE of that loop to one pass per second but would
// never end it, and it would feed the persistent retry queue on every pass —
// evicting real threat alerts, which is the CHAOS-27/64 failure class. Excluded
// here, the loop cannot form at all: the alert plane's own crash still gets the
// counter, the record, the log line and the audit entry, which is every sink
// except the one it cannot safely use.
var crashAlertSelfExcluded = map[string]bool{
	"alert":        true, // alerts.go fireAlert's own goroutine guard
	"alerts_retry": true, // internal/alerts/store.go retry-queue round
}

// fireComponentPanicAlert pages on a contained panic. Called from recordCrash
// INSIDE the throttle gate, so it inherits the sink's one-per-component-per-
// second bound.
//
// EVERYTHING outbound happens on a detached goroutine — the subscriber probe as
// well as the dispatch — and that is a correctness requirement, not a latency
// preference. The sink's contract is that it can never take down the process it
// protects, and blocking is as fatal to a worker as panicking: recordCrash is
// called from inside `runGuarded`, whose whole purpose is that a bad round costs
// one window instead of stalling the loop forever. A recordCrash that blocks
// turns the containment back into the "silent permanent stall" runGuarded's doc
// exists to remove, and on the admin plane it would hang the request before
// withAdminPanicRecovery writes its 500.
//
// The hazard is concrete, not theoretical. globalAlertStore.HasSubscriber takes
// the store's RWMutex, and Store.Add, Store.Update and Store.Delete release that
// WRITE lock with a non-deferred `as.mu.Unlock()` (internal/alerts/store.go) —
// the CHAOS-118 §8.2a lock-pairing shape. A panic inside one of those critical
// sections leaks the write lock, and a synchronous probe on the sink's stack
// would then deadlock the recovering goroutine against a lock nothing will ever
// release: no 500, no loop, and a goroutine leaked per subsequent crash. Off the
// stack, the leaked lock blocks only this page.
//
// The probe keeps earning its place inside the goroutine — it avoids Dispatch's
// dedup mutex and its O(n) expiry scan when nothing is subscribed — but the
// reason fireDNSFailureAlert puts the same gate on its own stack does not
// transfer: that producer fires once per REQUEST with no throttle in front of
// it, while this one is already bounded to one page per component per second, so
// the goroutine it may now spawn for nothing is bounded with it.
//
// Detail carries the COMPONENT and nothing else. Two independent reasons, both
// load-bearing:
//
//   - Secrets. recover()'s value can embed a credential (panic(cfg.SessionHMAC)
//     is the case this file's header names), which is why the raw value is kept
//     out of the log and masked on export. A webhook body leaves the box to a
//     third-party collector, so it is the LAST place that text may appear.
//   - Dedup. Store.Dispatch dedups on `event + ":" + Detail`. Putting the crash
//     ID — unique per crash by construction — in Detail would make every page a
//     distinct key that the 30 s window cannot suppress, and the fan-out would
//     land in the 500-entry retry queue where it evicts real threat alerts. That
//     is exactly the CHAOS-64 dns_failure defect. Keying on the component
//     instead means a repeatedly panicking round pages ONCE per 30 s window, and
//     the component set is bounded by maxCrashLabels because crashThrottleAllow
//     fails closed past it — so this producer can contribute at most that many
//     dedup keys.
//
// The cost is that the page does not carry the crash ID. The operator correlates
// through the `panic_recovered` audit entry on the same component, which does.
func fireComponentPanicAlert(component string) {
	// Both checks here are a plain map read and a plain var read. Neither takes
	// a lock, so neither can block the sink.
	if crashAlertSelfExcluded[component] {
		return
	}
	// nil only if a panic is recorded before this package's init has run, which
	// is a panic during package variable initialization: the process is dying
	// either way and the record still lands. Checked rather than assumed,
	// because the sink's contract is that it can never crash the process.
	page := crashAlertPage
	if page == nil {
		return
	}
	// Both seam reads happen HERE, on the sink's stack, not inside the goroutine:
	// a read inside it would be the very race the barrier exists to remove.
	var done func()
	if barrier := crashAlertPageBarrier; barrier != nil {
		done = barrier()
	}
	go func() {
		if done != nil {
			defer done()
		}
		page(component)
	}()
}

// crashAlertPayload builds the page body. Split out of the init closure so the
// bound component label is readable and assertable on its own.
func crashAlertPayload(component string) AlertPayload {
	label := component
	if len(label) > crashAlertDetailComponentMax {
		label = label[:crashAlertDetailComponentMax] + "…"
	}
	return AlertPayload{
		Actor: "system", // a background round has no request context
		Detail: "a panic in component " + sanitizeLog(label) + " was recovered and contained: the work in " +
			"flight was abandoned. A round that panics every window keeps this node up and reporting " +
			"healthy while its work never completes — check the panic_recovered audit entry for this " +
			"component and culvert_crash_records_total{component} for the rate",
		Source: "crashguard",
	}
}
