package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/redaction"
)

// fakeConn is a net.Conn whose Read behavior is injectable (panic / EOF), used to
// drive the relay engine into a goroutine panic without real sockets.
type fakeConn struct{ readFn func([]byte) (int, error) }

func (c *fakeConn) Read(b []byte) (int, error)       { return c.readFn(b) }
func (c *fakeConn) Write(b []byte) (int, error)      { return len(b), nil }
func (c *fakeConn) Close() error                     { return nil }
func (c *fakeConn) LocalAddr() net.Addr              { return dummyAddr{} }
func (c *fakeConn) RemoteAddr() net.Addr             { return dummyAddr{} }
func (c *fakeConn) SetDeadline(time.Time) error      { return nil }
func (c *fakeConn) SetReadDeadline(time.Time) error  { return nil }
func (c *fakeConn) SetWriteDeadline(time.Time) error { return nil }

type dummyAddr struct{}

func (dummyAddr) Network() string { return "fake" }
func (dummyAddr) String() string  { return "fake" }

func countPanicAudits() int {
	n := 0
	for _, e := range auditGet() {
		if e.Action == "panic_recovered" {
			n++
		}
	}
	return n
}

// ── Redaction / no-leak (RED-TEAM: secret in the panic value) ────────────────

func TestCrashRecord_RedactedNoLeak(t *testing.T) {
	resetCrashGuardStateForTest()
	const secret = "S3CR3T-HMAC-abc123"
	recordCrash("proxy", "corr-x", errors.New("bad token "+secret))

	masked := lastCrashRedacted(redaction.NewWithSalt([]byte("salt")))
	js, _ := json.Marshal(masked)
	if strings.Contains(string(js), secret) {
		t.Fatalf("redacted export leaked the secret: %s", js)
	}
	if !strings.Contains(string(js), "mask_") {
		t.Fatalf("summary was not masked on export: %s", js)
	}
	for _, e := range auditGet() {
		if e.Action == "panic_recovered" && strings.Contains(e.Detail, secret) {
			t.Fatal("audit detail leaked the secret panic value")
		}
	}
	var b strings.Builder
	crashByComponent.writePrometheus(&b)
	if strings.Contains(b.String(), secret) {
		t.Fatal("metric exposition leaked the secret")
	}
}

// ── Sink never propagates a re-panic (value whose Error() panics) ────────────

type panicStringer struct{}

func (panicStringer) Error() string { panic("Error() itself panics") }

func TestCrashSink_PanickingValueNoPropagate(t *testing.T) {
	resetCrashGuardStateForTest()
	// fmt.Sprint recovers a panicking Error()/String(); recordCrash must return.
	recordCrash("proxy", "", panicStringer{})
	if atomic.LoadInt64(&statCrashRecords) != 1 {
		t.Fatalf("record count=%d want 1 (metric must be lossless)", atomic.LoadInt64(&statCrashRecords))
	}
}

// ── PROXY plane: record-only, ErrAbortHandler re-panics ──────────────────────

func TestProxyGuard_RecordsButNeverWrites(t *testing.T) {
	resetCrashGuardStateForTest()
	rec := httptest.NewRecorder()
	func(w http.ResponseWriter) {
		defer proxyCrashGuard("corr-1")
		panic("boom PLAIN-SECRET")
	}(rec)
	if rec.Body.Len() != 0 {
		t.Fatalf("proxy guard must not write a body, got %q", rec.Body.String())
	}
	if atomic.LoadInt64(&statCrashRecords) != 1 {
		t.Fatal("expected exactly one crash record")
	}
}

func TestProxyGuard_ErrAbortRePanicsNoRecord(t *testing.T) {
	resetCrashGuardStateForTest()
	func() {
		defer func() {
			if r := recover(); r != http.ErrAbortHandler {
				t.Fatalf("expected re-panic of ErrAbortHandler, got %v", r)
			}
		}()
		defer proxyCrashGuard("id")
		panic(http.ErrAbortHandler)
	}()
	if atomic.LoadInt64(&statCrashRecords) != 0 {
		t.Fatal("ErrAbortHandler is an intentional abort — must not record a crash")
	}
}

func TestProxyGuard_NoPanicByteIdentical(t *testing.T) {
	resetCrashGuardStateForTest()
	rec := httptest.NewRecorder()
	func(w http.ResponseWriter) {
		defer proxyCrashGuard("id")
		w.Header().Set("X-Test", "1")
		w.WriteHeader(201)
		_, _ = w.Write([]byte("hello"))
	}(rec)
	if rec.Code != 201 || rec.Body.String() != "hello" || rec.Header().Get("X-Test") != "1" {
		t.Fatalf("happy path not byte-identical under the guard: code=%d body=%q", rec.Code, rec.Body.String())
	}
	if atomic.LoadInt64(&statCrashRecords) != 0 {
		t.Fatal("no-panic path must not record a crash")
	}
}

// ── ADMIN plane middleware ───────────────────────────────────────────────────

func TestAdminGuard_Clean500WhenUnwritten(t *testing.T) {
	resetCrashGuardStateForTest()
	h := withAdminPanicRecovery(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("admin boom")
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("code=%d want 500", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Internal Server Error") {
		t.Fatal("missing clean 500 body")
	}
}

func TestAdminGuard_NoDoubleCommit(t *testing.T) {
	resetCrashGuardStateForTest()
	h := withAdminPanicRecovery(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("partial-body"))
		panic("after commit")
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("committed status changed to %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "Internal Server Error") {
		t.Fatal("injected a 500 into an already-committed body")
	}
}

func TestAdminGuard_PreservesFlusherAndUnwrap(t *testing.T) {
	rec := httptest.NewRecorder()
	tw := &trackedRW{ResponseWriter: rec}
	if _, ok := interface{}(tw).(http.Flusher); !ok {
		t.Fatal("trackedRW must satisfy http.Flusher")
	}
	if err := http.NewResponseController(tw).Flush(); err != nil {
		t.Fatalf("ResponseController.Flush via Unwrap failed: %v", err)
	}
	if !rec.Flushed {
		t.Fatal("flush did not reach the underlying writer")
	}
}

// ── Anti-forensics: flood is throttled, audit ring not evicted ───────────────

func TestCrashFlood_Throttled(t *testing.T) {
	resetCrashGuardStateForTest()
	before := countPanicAudits()
	const N = 1200
	for i := 0; i < N; i++ {
		recordCrash("proxy", "", "repeatable panic")
	}
	if got := atomic.LoadInt64(&statCrashRecords); got != N {
		t.Fatalf("count lossy under flood: %d != %d", got, N)
	}
	if atomic.LoadInt64(&statCrashSuppressed) == 0 {
		t.Fatal("throttle never suppressed under a flood")
	}
	if added := countPanicAudits() - before; added > 3 {
		t.Fatalf("flood not throttled: %d audit entries added (SIEM/ring flood)", added)
	}
}

// ── Counter overflow bucket + bounds + exposition ────────────────────────────

func TestCrashCounter_OverflowBucket(t *testing.T) {
	resetCrashGuardStateForTest()
	for i := 0; i < maxCrashLabels+10; i++ {
		crashByComponent.record(fmt.Sprintf("dyn-%d", i)) // must not nil-deref
	}
	var b strings.Builder
	crashByComponent.writePrometheus(&b)
	if !strings.Contains(b.String(), `component="other"`) {
		t.Fatal("label overflow did not fold into component=\"other\"")
	}
}

func TestCrashRecord_BoundsEnforced(t *testing.T) {
	resetCrashGuardStateForTest()
	recordCrash("proxy", "", strings.Repeat("A", 5000))
	rec, ok := lastCrashSnapshot()
	if !ok {
		t.Fatal("no crash record")
	}
	if len(rec.Summary) > crashMsgMax+len("…(truncated)") {
		t.Fatalf("summary not bounded: %d", len(rec.Summary))
	}
	if len(rec.Stack) > crashStackMax {
		t.Fatalf("stack not bounded: %d", len(rec.Stack))
	}
}

func TestCrashMetric_Exposition(t *testing.T) {
	resetCrashGuardStateForTest()
	recordCrash("proxy", "", "x")
	recordCrash("admin", "", "y")
	var b strings.Builder
	crashByComponent.writePrometheus(&b)
	s := b.String()
	for _, want := range []string{
		`culvert_crash_records_total{component="proxy"}`,
		"culvert_crash_records_suppressed_total",
		"culvert_crash_sink_panics_total",
		"# TYPE culvert_crash_records_total counter",
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("exposition missing %q:\n%s", want, s)
		}
	}
}

// ── Relay-goroutine panic (RED-TEAM): no deadlock, no leak ───────────────────

func TestRelayPanic_NoDeadlock(t *testing.T) {
	resetCrashGuardStateForTest()
	base := runtime.NumGoroutine()
	panicConn := &fakeConn{readFn: func([]byte) (int, error) { panic("relay leg exploded") }}
	eofConn := &fakeConn{readFn: func([]byte) (int, error) { return 0, io.EOF }}

	fin := make(chan struct{})
	go func() {
		// aSrc=panicConn (panics on Read) drives one relay leg into a panic.
		bidiRelayCounted(eofConn, panicConn, panicConn, eofConn)
		close(fin)
	}()
	select {
	case <-fin:
	case <-time.After(3 * time.Second):
		t.Fatal("bidiRelayCounted deadlocked after a relay-goroutine panic")
	}
	if atomic.LoadInt64(&statCrashRecords) == 0 {
		t.Fatal("relay panic was not recorded")
	}
	// allow the two relay goroutines to unwind
	for i := 0; i < 50 && runtime.NumGoroutine() > base+2; i++ {
		time.Sleep(10 * time.Millisecond)
	}
	if n := runtime.NumGoroutine(); n > base+2 {
		t.Fatalf("relay goroutines leaked: base=%d now=%d", base, n)
	}
}

// ── Anti-drift wall: a bare `go` in a hot-path file must carry recover ───────

func TestNoBareGoWithoutRecover(t *testing.T) {
	for _, f := range []string{"proxy.go", "proxy_tunnel.go", "socks5.go", "alerts.go"} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		s := string(b)
		if !strings.Contains(s, "\tgo ") {
			continue // no goroutine spawns in this file
		}
		if !strings.Contains(s, "recoverGoroutine(") && !strings.Contains(s, "recover()") {
			t.Errorf("%s spawns goroutines but carries no panic recovery — crashguard drift", f)
		}
	}
}
