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

	"github.com/KidCarmi/Culvert/internal/redaction"
)

const (
	crashMsgMax        = 512         // bound the (attacker-shaped) panic value
	crashStackMax      = 4096        // bound debug.Stack()
	maxCrashLabels     = 32          // component-label cardinality cap
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
}

// crashThrottleAllow is a token-per-interval gate per component. The first hit of
// each component always passes; subsequent hits within crashThrottleEvery are
// gated. The map is bounded to the fixed component set so it cannot grow unbounded.
func crashThrottleAllow(component string) bool {
	now := time.Now().UnixNano()
	crashThrottleMu.Lock()
	defer crashThrottleMu.Unlock()
	last, ok := crashThrottleLast[component]
	if ok && now-last < int64(crashThrottleEvery) {
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
			recordCrash("admin", r.Header.Get("X-Request-ID"), v)
			if !tw.wrote { // never double-commit / never inject into a streamed body
				http.Error(tw.ResponseWriter, "Internal Server Error", http.StatusInternalServerError)
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
