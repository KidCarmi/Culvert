package main

// Security regression gates for the cdr_unavailable producer.
//
// cdrHandleCallError runs once per inspected response body whose Sluice
// Sanitize call failed — the request path of an in-line gateway — and it used
// to fire with:
//
//	Detail: fmt.Sprintf("sluice call failed: %v", err)
//
// A gRPC error's text embeds the ephemeral local port on the transport path
// ("… dial tcp 127.0.0.1:54012 …") and, for a server-produced status, a
// REMOTE-SUPPLIED description. The alert store dedups on "event:detail" within
// a 30 s window (internal/alerts, Q17/CHAOS-27), so that made a distinct dedup
// key per request: dedup could not suppress a Sluice outage by construction,
// and every delivery landed in the 500-entry retry queue, where a CDR fault
// evicts real threat_detected alerts (register rows WK-12/RS-5). The producer
// was also ungated, so in the default posture (no webhooks) every failed
// sanitize paid a goroutine, a payload build and a round trip through the
// process-wide dedup mutex to deliver to nobody.
//
// The log line carrying the cause was additionally written with a raw %v, so a
// Sluice-supplied status description containing a newline could forge a second
// process-log record (CWE-117); it is sanitised and rate-limited now.

import (
	"errors"
	"fmt"
	"math"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// withCDRAlertStore swaps in a fresh process-wide alert store for the test and
// restores the original, so a gate never inherits another test's webhooks or
// dedup state.
func withCDRAlertStore(t *testing.T) *AlertStore {
	t.Helper()
	old := globalAlertStore
	fresh := &AlertStore{}
	globalAlertStore = fresh
	t.Cleanup(func() { globalAlertStore = old })
	return fresh
}

// resetCDRLogGate clears the rate gate so a gate's own line is never suppressed
// by an earlier test's, and restores it afterwards.
func resetCDRLogGate(t *testing.T) {
	t.Helper()
	old := cdrCallErrorLogAt.Load()
	cdrCallErrorLogAt.Store(0)
	t.Cleanup(func() { cdrCallErrorLogAt.Store(old) })
}

// fireAlertRecorder observes the DISPATCH DECISION through the fireAlert var —
// the seam alerts.go documents for exactly this, so a gate never depends on
// webhook HTTP delivery or on the package-global delivery semaphore.
type fireAlertRecorder struct {
	mu   sync.Mutex
	seen []recordedFire
}

type recordedFire struct{ event, detail string }

func (r *fireAlertRecorder) details(event string) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []string
	for _, f := range r.seen {
		if f.event == event {
			out = append(out, f.detail)
		}
	}
	return out
}

// wait polls until at least n events of that name are recorded, or fails.
func (r *fireAlertRecorder) wait(t *testing.T, n int, event string) []string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		got := r.details(event)
		if len(got) >= n {
			return got
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %d %s alerts, saw %d", n, event, len(got))
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// recordFireAlert swaps the fireAlert var for a recorder that ALSO performs the
// real dispatch, so the alert store's dedup accounting stays exercised.
func recordFireAlert(t *testing.T) *fireAlertRecorder {
	t.Helper()
	rec := &fireAlertRecorder{}
	old := fireAlert
	fireAlert = func(event string, payload AlertPayload) {
		rec.mu.Lock()
		rec.seen = append(rec.seen, recordedFire{event: event, detail: payload.Detail})
		rec.mu.Unlock()
		old(event, payload)
	}
	t.Cleanup(func() { fireAlert = old })
	return rec
}

// TestCDRCallErrorClass_IsBoundedAcrossEphemeralPortsAndDescriptions is the
// primary regression gate: one Sluice outage seen over many connections, and
// one server that varies its description, must each produce ONE dedup key.
//
// Verified failing against the reintroduced `fmt.Sprintf("sluice call failed:
// %v", err)` shape.
func TestCDRCallErrorClass_IsBoundedAcrossEphemeralPortsAndDescriptions(t *testing.T) {
	transport := map[string]bool{}
	server := map[string]bool{}
	for i := range 200 {
		transport[cdrCallErrorClass(status.Error(codes.Unavailable,
			fmt.Sprintf("connection error: desc = \"transport: Error while dialing dial tcp 127.0.0.1:%d: connect: connection refused\"", 40000+i)))] = true
		server[cdrCallErrorClass(status.Error(codes.Internal,
			fmt.Sprintf("sanitize failed for object %d", i)))] = true
	}
	if len(transport) != 1 {
		t.Fatalf("200 dials of one outage produced %d distinct alert dedup keys (%v)", len(transport), transport)
	}
	if len(server) != 1 {
		t.Fatalf("200 server-worded failures produced %d distinct alert dedup keys (%v): the remote "+
			"end must not be able to choose this node's dedup keys", len(server), server)
	}
}

// TestCDRCallErrorClass_IsTheStatusCode pins the chosen class and its fixed
// cardinality, including the non-status and nil arms.
func TestCDRCallErrorClass_IsTheStatusCode(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want string
	}{
		{"unavailable", status.Error(codes.Unavailable, "down"), codes.Unavailable.String()},
		{"deadline", status.Error(codes.DeadlineExceeded, "slow"), codes.DeadlineExceeded.String()},
		{"internal", status.Error(codes.Internal, "boom"), codes.Internal.String()},
		{"resource exhausted", status.Error(codes.ResourceExhausted, "full"), codes.ResourceExhausted.String()},
		// A plain error is NOT a gRPC status: it must fold to one class rather
		// than carry its own text into the key.
		{"plain error folds", errors.New("read tcp 127.0.0.1:54012->127.0.0.1:50051: reset"), "unknown"},
		{"nil", nil, "unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := cdrCallErrorClass(tc.err); got != tc.want {
				t.Fatalf("cdrCallErrorClass = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestCDRCallErrorClass_ClampsNoncanonicalCodes is the regression gate for the
// hole in the FIRST version of this bound (Codex review, PR #1483): the class
// was st.Code().String(), taken on the belief that the protocol fixes its
// cardinality. It does not. grpc-go parses the `grpc-status` header with
// ParseInt and stores codes.Code(uint32(code)) with NO range check — only a
// non-numeric value is refused — and Code.String() renders anything outside
// 0..16 as "Code(<n>)". A faulty or hostile Sluice varying that number per
// response therefore minted a distinct alert dedup key per response: the exact
// retry-queue flooding this change exists to close, reintroduced inside it.
//
// Verified failing against the unclamped shape: 300 noncanonical codes produced
// 300 distinct keys.
func TestCDRCallErrorClass_ClampsNoncanonicalCodes(t *testing.T) {
	seen := map[string]bool{}
	for i := uint32(0); i < 300; i++ {
		// Stays in uint32 throughout — codes.Code's own underlying type — so the
		// deliberate noncanonical value needs no overflow-conversion suppression.
		code := codes.Code(uint32(cdrMaxCanonicalStatusCode) + 1 + i)
		got := cdrCallErrorClass(status.Error(code, "boom"))
		seen[got] = true
		if got != "unknown" {
			t.Fatalf("cdrCallErrorClass(code %d) = %q, want %q — a peer-chosen integer "+
				"must never reach the dedup key", code, got, "unknown")
		}
	}
	if len(seen) != 1 {
		t.Fatalf("300 noncanonical codes produced %d distinct dedup keys: %v", len(seen), seen)
	}
	// The extremes of the uint32 the transport will accept.
	for _, code := range []codes.Code{codes.Code(17), codes.Code(1000), codes.Code(math.MaxUint32)} {
		if got := cdrCallErrorClass(status.Error(code, "boom")); got != "unknown" {
			t.Errorf("cdrCallErrorClass(code %d) = %q, want %q", code, got, "unknown")
		}
	}
}

// TestCDRCallErrorClass_CanonicalRangeMatchesTheLibrary pins cdrMaxCanonicalStatusCode
// against grpc-go itself, because the library's own `_maxCode` is unexported and a
// hardcoded bound rots silently in BOTH directions.
//
// Every code at or below the bound must render a real NAME (so the clamp never
// folds a genuine status into "unknown"), and the first code above it must render
// the synthetic "Code(n)" form (so a grpc-go release that adds a canonical code
// fails here instead of being silently discarded). Same discipline as CHAOS-50's
// empirical badger message table: the assumption about a dependency IS the test.
func TestCDRCallErrorClass_CanonicalRangeMatchesTheLibrary(t *testing.T) {
	for c := codes.Code(0); c <= cdrMaxCanonicalStatusCode; c++ {
		name := c.String()
		if strings.HasPrefix(name, "Code(") {
			t.Errorf("codes.Code(%d).String() = %q: the bound claims this code is canonical", c, name)
		}
		if c == codes.OK {
			// status.Error(codes.OK, …) returns NIL by construction, so OK can
			// never reach the class from a call failure; cdrCallErrorClass(nil)
			// answers "unknown", which is the right answer for "no error".
			if got := cdrCallErrorClass(status.Error(c, "boom")); got != "unknown" {
				t.Errorf("cdrCallErrorClass(OK) = %q, want %q", got, "unknown")
			}
			continue
		}
		if got := cdrCallErrorClass(status.Error(c, "boom")); got != name {
			t.Errorf("cdrCallErrorClass(code %d) = %q, want the library's %q", c, got, name)
		}
	}
	next := cdrMaxCanonicalStatusCode + 1
	if name := next.String(); !strings.HasPrefix(name, "Code(") {
		t.Fatalf("codes.Code(%d).String() = %q — grpc-go added a canonical code above "+
			"cdrMaxCanonicalStatusCode, so the clamp is now discarding a real status. "+
			"Raise the constant.", next, name)
	}
}

// TestCDRCallErrorClass_CarriesNoRemoteText is the malformed/hostile-input
// gate: whatever Sluice puts in its status description, none of it may reach
// the dedup key.
func TestCDRCallErrorClass_CarriesNoRemoteText(t *testing.T) {
	marker := "SLUICE-SUPPLIED-MARKER"
	hostile := status.Error(codes.Internal, "boom "+marker+"\nforged: second record")
	got := cdrCallErrorClass(hostile)
	if strings.Contains(got, marker) || strings.ContainsAny(got, "\r\n") {
		t.Fatalf("cdrCallErrorClass leaked remote text or a newline into the dedup key: %q", got)
	}
}

// TestNoteCDRCallError_NoSubscriberNoDispatch pins the HasSubscriber gate.
// With no webhook subscribing, Dispatch must never be reached — observable as
// the process-wide dedup map not growing (Dispatch records a key before it
// looks at the hooks).
func TestNoteCDRCallError_NoSubscriberNoDispatch(t *testing.T) {
	withCDRAlertStore(t)
	resetCDRLogGate(t)
	rec := recordFireAlert(t)

	for i := range 25 {
		noteCDRCallError(status.Error(codes.Unavailable, fmt.Sprintf("down %d", i)))
	}
	// A negative needs a positive control to be worth anything: fire one alert
	// through the same seam and wait for it. Once the control has landed, any
	// goroutine the loop spawned has had at least as long to land too.
	go fireAlert("cdr_probe_control", AlertPayload{Detail: "control"})
	rec.wait(t, 1, "cdr_probe_control")

	if got := rec.details("cdr_unavailable"); len(got) != 0 {
		t.Fatalf("Dispatch was reached %d time(s) with no subscriber: the default posture is no "+
			"webhooks, and a producer whose rate is set by a fault must not pay for a delivery to nobody", len(got))
	}
}

// TestNoteCDRCallError_SubscribedFiresOneDedupKey is the end-to-end form and
// the CONTROL for the gate above: with a subscriber the alert must still fire,
// and a sustained outage must collapse to ONE dedup key rather than one per
// request.
func TestNoteCDRCallError_SubscribedFiresOneDedupKey(t *testing.T) {
	store := withCDRAlertStore(t)
	resetCDRLogGate(t)
	store.Add(AlertWebhook{URL: "https://example.invalid/hook", Events: []string{"cdr_unavailable"}, Enabled: true})
	rec := recordFireAlert(t)

	const fires = 40
	for i := range fires {
		noteCDRCallError(status.Error(codes.Unavailable,
			fmt.Sprintf("connection error: dial tcp 127.0.0.1:%d: connection refused", 45000+i)))
	}
	// Wait for ALL of them, not for the first: reading the key count as soon as
	// one dispatch has landed passes against the unbounded shape by luck.
	got := rec.wait(t, fires, "cdr_unavailable")
	if len(got) != fires {
		t.Fatalf("%d of %d subscribed alerts reached Dispatch", len(got), fires)
	}

	distinct := map[string]bool{}
	for _, d := range got {
		distinct[d] = true
	}
	if len(distinct) != 1 {
		t.Fatalf("%d distinct dedup keys for %d failures of one outage, want 1 — a key per request "+
			"cannot be suppressed and floods the bounded retry queue: %v", len(distinct), fires, distinct)
	}
	if tracked := store.DedupTracked(); tracked != 1 {
		t.Fatalf("the alert store tracked %d dedup keys, want 1", tracked)
	}
}

// TestNoteCDRCallError_LogIsRateLimited pins the request-path half. The line is
// emitted once per cdrCallErrorLogInterval; internal/logsink BLOCKS a producer
// on a full queue, so an unbounded line adds latency to every proxied response
// while Sluice is unwell. The gate drives the primitive directly, so it is
// deterministic.
func TestNoteCDRCallError_LogIsRateLimited(t *testing.T) {
	withCDRAlertStore(t)
	resetCDRLogGate(t)

	if cdrCallErrorLogAt.Load() != 0 {
		t.Fatal("gate not reset")
	}
	noteCDRCallError(status.Error(codes.Unavailable, "first"))
	first := cdrCallErrorLogAt.Load()
	if first == 0 {
		t.Fatal("onset must be logged immediately: a degradation must never start silently")
	}
	for range 50 {
		noteCDRCallError(status.Error(codes.Unavailable, "more"))
	}
	if cdrCallErrorLogAt.Load() != first {
		t.Fatal("a line was emitted inside the rate window")
	}
	// Age the gate: the next line is allowed again.
	cdrCallErrorLogAt.Store(time.Now().Add(-2 * cdrCallErrorLogInterval).UnixNano())
	noteCDRCallError(status.Error(codes.Unavailable, "later"))
	if cdrCallErrorLogAt.Load() == first {
		t.Fatal("no line was emitted after the rate window passed")
	}
}

// TestCDRHandleCallError_PostureIsUnchanged is the CONTROL for the whole
// change: the cheapest way to pass every gate above is to stop reporting the
// fault, and the second cheapest is to change what a failed sanitize DOES. The
// oversize branch must still skip, and a transport fault must still be counted
// as a CDR error and routed through fail_mode.
func TestCDRHandleCallError_PostureIsUnchanged(t *testing.T) {
	withCDRAlertStore(t)
	resetCDRLogGate(t)

	oversizeBefore := atomic.LoadInt64(&statCDROversizeSkipped)
	res := cdrHandleCallError(status.Error(codes.InvalidArgument, "file_too_large: 900MB"),
		"p", "m", 12, CDRConfig{})
	if res == nil || res.Outcome != cdrPass {
		t.Fatalf("oversize must still pass through as a skip, got %+v", res)
	}
	if atomic.LoadInt64(&statCDROversizeSkipped)-oversizeBefore != 1 {
		t.Fatal("oversize must still be counted as a skip, not as a CDR error")
	}

	errBefore := atomic.LoadInt64(&statCDRErrors)
	res = cdrHandleCallError(status.Error(codes.Unavailable, "sluice down"), "p", "m", 12, CDRConfig{})
	if res == nil {
		t.Fatal("a transport fault must still produce an outcome")
	}
	if atomic.LoadInt64(&statCDRErrors)-errBefore != 1 {
		t.Fatal("a transport fault must still be counted as a CDR error")
	}
}
