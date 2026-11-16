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

	crashAlertMu   sync.Mutex
	crashAlertLast = map[string]int64{} // component -> last panic_contained emit UnixNano
)

// CHAOS-120: the crash plane's NOTIFICATION boundary.
//
// CHAOS-116/117/118/119 each closed a hole in what an operator can SEE after a
// contained panic, and each one ended by recording the same residual: nothing
// TELLS them. The sink below writes a counter, a log line and an audit entry,
// and until this round it fired no alert for any of the 63 components that
// funnel into it. Exactly one contained-panic round alerted, and it did so
// itself rather than through the sink — HAState.notePanicRound, whose own
// doc comment states the general rule this round generalises:
//
//	without them the containment would trade a loud crash for a silent one,
//	which is the failure class the guard exists to remove
//
// guardedTick says the same thing from the other side: "the cost of not
// counting is that a permanently panicking standby never escalates on its own,
// so the containment is reported instead: crash record + counter + the
// sync_panics status field, and a fire-once ha_sync_panic alert". Three of
// those four signals were sink-wide. The alert was not.
const (
	// alertEventPanicContained is the operator-facing event for ANY contained
	// panic. Deliberately plane-neutral: the sink serves the proxy, admin and
	// detached-goroutine planes alike, and the component is in the payload
	// rather than in the event name, so a subscriber gets one row to tick
	// instead of 63 and the vocabulary cannot drift as rounds add components.
	alertEventPanicContained = "panic_contained"

	// crashAlertRearm latches one alert per component, then re-arms. The sink's
	// own crashThrottleEvery is ONE SECOND, which is the right bound for a log
	// line and the wrong one for a webhook: a deterministically crash-looping
	// round would deliver 86,400 alerts a day and the operator would mute the
	// event, which is the same outcome as not shipping it. An hour is long
	// enough that a crash loop is one page, and short enough that a recurrence
	// the next day is new information rather than a swallowed repeat. The
	// REPEAT RATE is not lost by latching — culvert_crash_records_total
	// {component} counts every occurrence, including the latched ones.
	crashAlertRearm = time.Hour
)

// crashComponentAlert and crashComponentAlertsRetry label the alert-DELIVERY
// plane's own contained panics (alerts.go's fireAlert recover, and
// internal/alerts' retry-loop SafeCall). They are constants rather than
// literals because notePanicContained has to name them: see crashAlertExcluded.
const (
	crashComponentAlert       = "alert"
	crashComponentAlertsRetry = "alerts_retry"
)

// crashAlertExcluded reports whether a component must never raise
// panic_contained.
//
// The alert-delivery plane excludes itself, for two independent reasons.
//
//  1. It cannot work. An alert saying "the thing that delivers alerts just
//     panicked" is dispatched BY the thing that just panicked. There is no
//     delivery path left to carry it.
//  2. It feeds back. fireAlert's own recover is recoverGoroutine("alert"), so
//     a dispatch that panics re-enters this sink as component "alert". Firing
//     from there would spawn another dispatch, which panics again, which
//     re-enters the sink — a self-sustaining loop clocked by crashThrottleEvery
//     at one iteration per second, forever, each iteration a fresh goroutine
//     and a fresh webhook attempt. The crashAlertRearm latch alone would bound
//     it to one extra hop, which is survivable; the exclusion makes it zero,
//     which is correct.
//
// The loss is accepted and it is not silent: a broken alert plane still shows
// up as culvert_crash_records_total{component="alert"}, a PANIC_RECOVERED log
// line and a system-actor audit entry. An operator cannot be PAGED about their
// pager being down by their pager.
func crashAlertExcluded(component string) bool {
	return component == crashComponentAlert || component == crashComponentAlertsRetry
}

// crashAlertAllow is the per-component fire-once latch, re-arming after
// crashAlertRearm.
//
// CHAOS-84's lesson applies here exactly as it does to crashThrottleAllow: the
// comparison is on MAGNITUDE, so a backward wall-clock step suppresses for one
// window in either direction instead of latching the component out until the
// clock catches up.
//
// The map cannot grow past the sink's label cap, and the cap can never be the
// binding constraint on this path: recordCrash only reaches here when
// crashThrottleAllow has already admitted the component, so crashAlertLast's
// key set is a subset of crashThrottleLast's. The bound is restated anyway —
// it is one comparison, and a later caller that reaches this helper directly
// must not be able to grow the map without limit.
func crashAlertAllow(component string) bool {
	now := time.Now().UnixNano()
	crashAlertMu.Lock()
	defer crashAlertMu.Unlock()
	last, ok := crashAlertLast[component]
	if ok && time.Duration(now-last).Abs() < crashAlertRearm {
		return false
	}
	if !ok && len(crashAlertLast) >= maxCrashLabels {
		return false
	}
	crashAlertLast[component] = now
	return true
}

// firePanicContainedAlert dispatches ONE panic_contained alert. A package-level
// seam for the reason fireAdminUIListenerAlert is one: a test observes the
// dispatch DECISION synchronously instead of racing the process-global sink.
//
// The subscriber gate is INSIDE the goroutine, and that placement is the
// finding this round made against its own first design. Every other
// fault-driven producer gates before the `go`, to keep a degraded node from
// spawning a goroutine per request in the default posture. Doing that here
// would put globalAlertStore's mutex on the crash-sink path, and the alert
// store releases it with a BARE trailing Unlock in Add/Update/Delete —
// deliberately, so the fsync lands outside the lock, and it is the CHAOS-118
// §7.4 shape. A panic inside one of those critical sections strands as.mu
// held, unwinds to withAdminPanicRecovery, and re-enters recordCrash: a gate
// on the sink path would then block the sink FOREVER on a mutex the panic
// itself stranded, hanging the admin request and losing the one crash record
// that explains it. The sink must acquire no lock owned by a plane that may
// have panicked while holding it (TestCHAOS120_CrashSinkTakesNoForeignLock
// pins this). The gate's usual rationale does not apply anyway: this producer
// is latched to one dispatch per component per hour, not one per request.
//
// The payload carries the component and the crash id and NOTHING ELSE. The
// panic value is never included, for the reason the ERROR log line gives: it
// can embed a credential (panic(cfg.SessionHMAC)), sanitizeLog scrubs control
// characters rather than masking secrets, and a webhook is an EGRESS to a
// third party. The crash id is the join key to the local evidence.
// It dispatches through globalAlertStore directly rather than through main's
// fireAlert wrapper, because routing it through that var closes a package-level
// initialization CYCLE the compiler rejects outright: fireAlert refers to
// recoverGoroutine, which refers to recordCrash, which now refers back here.
// The two are otherwise identical — fireAlert is `recover` + the same Dispatch
// — and this goroutine carries that recover itself, on the line below.
//
// The subscriber gate names its event as a LITERAL on purpose. CHAOS-113's
// differential oracle discovers the alert vocabulary by scanning the tree for
// exactly these call shapes with a quoted event, and resolves no constants, so
// a constant here would make that gate pass VACUOUSLY for this event — the one
// gate whose whole job is to prove an operator can subscribe to it.
func dispatchPanicContainedAlert(component, crashID string) {
	go func() {
		defer recoverGoroutine(crashComponentAlert)
		if !globalAlertStore.HasSubscriber("panic_contained") {
			return
		}
		globalAlertStore.Dispatch(alertEventPanicContained, AlertPayload{
			Event:  alertEventPanicContained,
			Actor:  "system",
			Host:   component,
			Detail: "a panic was recovered and contained in component " + component + " (crash_id=" + crashID + "); this component's round did not complete and may be degraded until the node is restarted — see culvert_crash_records_total{component} for the repeat rate",
			Source: "crashguard",
		})
	}()
}

// firePanicContainedAlert is the seam tests replace. It is assigned in init
// rather than in its declaration because a declaration initializer referring
// to dispatchPanicContainedAlert closes the same package-level initialization
// cycle described above (var -> dispatch -> recoverGoroutine -> recordCrash ->
// notePanicContained -> var); an init body is not part of that graph.
var firePanicContainedAlert func(component, crashID string)

func init() { firePanicContainedAlert = dispatchPanicContainedAlert }

// notePanicContained decides whether a contained panic raises an alert. Called
// from recordCrash AFTER the record, log line and audit entry are committed, so
// the notification can never delay or displace the durable evidence.
func notePanicContained(component, crashID string) {
	if crashAlertExcluded(component) || !crashAlertAllow(component) {
		return
	}
	// Fails toward DELIVERY, for the reason alerts.HasSubscriber does: a seam
	// left nil by a test that forgot to restore it must not be able to silence
	// a real alert in a later test, and must not nil-deref the sink.
	if fn := firePanicContainedAlert; fn != nil {
		fn(component, crashID)
		return
	}
	dispatchPanicContainedAlert(component, crashID)
}

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

	// CHAOS-120: and TELL someone. Last, so the durable evidence above is
	// already committed; non-blocking, so a webhook cannot slow the sink.
	notePanicContained(component, rec.ID)
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
	crashAlertMu.Lock()
	crashAlertLast = map[string]int64{}
	crashAlertMu.Unlock()
	lastCrashMu.Lock()
	lastCrash = nil
	lastCrashMu.Unlock()
}
